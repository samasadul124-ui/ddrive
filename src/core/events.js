/**
 * Event bus + serverless/webhook delivery.
 *
 * `emit()` fans an event out to
 *   1. in-process subscribers (replication, tiering, metrics, ...)
 *   2. configured targets (`event_target`): HTTP webhooks or "function"
 *      endpoints that receive an AWS Lambda style payload, signed with
 *      HMAC-SHA256 so receivers can verify authenticity.
 *
 * Delivery is durable: each attempt is recorded in `event_delivery` with
 * exponential backoff, and events that exhaust their retries land in the dead
 * letter queue (status `dead`) where the console/API can redrive them.
 */
const { randomUUID } = require('crypto')
const util = require('../lib/util')

const S3_EVENT_NAMES = {
    OBJECT_CREATED: 's3:ObjectCreated:Put',
    OBJECT_MOVED: 's3:ObjectCreated:Copy',
    OBJECT_COPIED: 's3:ObjectCreated:Copy',
    OBJECT_REMOVED: 's3:ObjectRemoved:Delete',
    OBJECT_DELETE_MARKER_CREATED: 's3:ObjectRemoved:DeleteMarkerCreated',
    OBJECT_TAGGING: 's3:ObjectTagging:Put',
    OBJECT_RESTORE: 's3:ObjectRestore:Post',
    OBJECT_TIER_CHANGED: 's3:ObjectTiering:Transition',
    BUCKET_CREATED: 's3:BucketCreated',
    BUCKET_REMOVED: 's3:BucketRemoved',
    BUCKET_UPDATED: 's3:BucketUpdated',
    BUCKET_POLICY_UPDATED: 's3:BucketPolicyUpdated',
    BUCKET_POLICY_REMOVED: 's3:BucketPolicyRemoved',
    VERSION_REMOVED: 's3:ObjectVersionDeleted',
    DIRECTORY_CREATED: 's3:FolderCreated',
    DIRECTORY_REMOVED: 's3:FolderRemoved',
    OBJECT_METADATA_UPDATED: 's3:ObjectMetadataUpdated',
    LIFECYCLE_TRANSITION: 's3:LifecycleTransition',
    LIFECYCLE_EXPIRATION: 's3:LifecycleExpiration',
    REPLICATION_COMPLETED: 's3:ReplicationCompleted',
    REPLICATION_FAILED: 's3:ReplicationFailed',
}

const createEvents = (deps = {}) => {
    const {
        repo, logger = console, metrics, intervalMs = 2000, batchSize = 20, maxRetriesDefault = 5,
    } = deps
    const subscribers = []
    const counters = { emitted: 0, delivered: 0, failed: 0, dead: 0 }

    const subscribe = (handler) => {
        subscribers.push(handler)

        return () => {
            const idx = subscribers.indexOf(handler)
            if (idx >= 0) subscribers.splice(idx, 1)
        }
    }

    const buildPayload = (type, payload) => {
        const bucket = payload.bucket || {}
        const node = payload.node || {}
        const eventName = S3_EVENT_NAMES[type] || type
        const actor = payload.actor || {}

        return {
            version: '1.0',
            id: randomUUID(),
            type,
            eventName,
            time: util.iso(new Date()),
            region: bucket.region || 'primary',
            bucket: bucket.name || null,
            bucketId: bucket.id || null,
            key: node.path || payload.path || null,
            objectId: node.id || null,
            versionId: payload.versionId || null,
            size: payload.size ?? node.size ?? null,
            etag: node.etag || null,
            actor: actor.name || actor.id ? { id: actor.id || null, name: actor.name || null, type: actor.type || 'user' } : null,
            detail: payload.detail || payload.patch || null,
            source: { service: 'ddrive', protocol: actor.protocol || null, requestId: actor.requestId || null },
        }
    }

    /** Store event as S3-compatible JSON for "function" targets. */
    const toS3Record = (event) => ({
        eventVersion: '2.1',
        eventSource: 'ddrive:s3',
        awsRegion: event.region,
        eventTime: event.time,
        eventName: event.eventName,
        s3: {
            s3SchemaVersion: '1.0',
            configurationId: 'ddrive',
            bucket: { name: event.bucket, ownerIdentity: { principalId: event.actor?.id || 'system' }, arn: `arn:ddrive:s3:::${event.bucket}` },
            object: {
                key: encodeURIComponent(event.key || '').replace(/%2F/g, '/'),
                size: event.size,
                eTag: event.etag,
                versionId: event.versionId,
            },
        },
        ddrive: event,
    })

    const matchingTargets = async (event) => {
        const targets = await repo.find('event_target', { status: 'enabled' })
        return targets.filter((target) => {
            if (target.bucketId && target.bucketId !== event.bucketId) return false
            if (target.prefix && !String(event.key || '').startsWith(target.prefix)) return false
            const events = target.events || ['*']
            if (events.includes('*')) return true
            if (events.includes(event.type) || events.includes(event.eventName)) return true
            // allow wildcards such as "s3:ObjectCreated:*" or "OBJECT_*"
            return events.some((pattern) => {
                if (!pattern.includes('*')) return false
                const regex = new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`)

                return regex.test(event.type) || regex.test(event.eventName)
            })
        })
    }

    const emit = async (type, rawPayload = {}) => {
        counters.emitted += 1
        metrics?.inc('ddrive_events_emitted_total', 1, { type })
        const event = buildPayload(type, rawPayload)

        // in-process subscribers run first: they must never block the data plane
        subscribers.forEach((handler) => {
            Promise.resolve()
                .then(() => handler(type, rawPayload, event))
                .catch((err) => logger.warn?.({ err, type }, 'event subscriber failed'))
        })

        try {
            const targets = await matchingTargets(event)
            if (targets.length) {
                await repo.insertMany('event_delivery', targets.map((target) => ({
                    targetId: target.id,
                    eventId: event.id,
                    eventType: event.type,
                    payload: event,
                    status: 'pending',
                    attempts: 0,
                    nextAttemptAt: new Date(),
                })))
            }
        } catch (err) {
            logger.warn?.({ err, type }, 'failed to queue event delivery')
        }

        return event
    }

    const sign = (secret, body) => `sha256=${util.hmacSha256(secret, body)}`

    const deliverOne = async (delivery) => {
        const target = await repo.findOne('event_target', { id: delivery.targetId })
        if (!target || target.status !== 'enabled') {
            await repo.update('event_delivery', { id: delivery.id }, {
                status: 'dead', lastError: 'target missing or disabled', nextAttemptAt: null,
            })

            return false
        }
        const record = target.type === 'function'
            ? { Records: [toS3Record(delivery.payload)] }
            : delivery.payload
        const body = JSON.stringify(record)
        const headers = {
            'content-type': 'application/json',
            'x-ddrive-event': delivery.eventType,
            'x-ddrive-delivery': delivery.id,
            'x-ddrive-event-id': delivery.payload.id,
            ...(target.secret ? { 'x-ddrive-signature': sign(target.secret, body) } : {}),
            ...(target.headers || {}),
        }
        try {
            const res = await fetch(target.url, {
                method: 'POST',
                headers,
                body,
                signal: AbortSignal.timeout(target.timeoutMs || 10000),
            })
            if (!res.ok) throw new Error(`target responded with ${res.status}`)
            await repo.update('event_delivery', { id: delivery.id }, {
                status: 'delivered', attempts: Number(delivery.attempts) + 1, responseCode: res.status, deliveredAt: new Date(), nextAttemptAt: null,
            })
            counters.delivered += 1
            metrics?.inc('ddrive_events_delivered_total', 1, { target: target.name })

            return true
        } catch (err) {
            const attempts = Number(delivery.attempts) + 1
            const maxRetries = target.maxRetries === undefined || target.maxRetries === null
                ? maxRetriesDefault
                : Number(target.maxRetries)
            const dead = attempts >= maxRetries
            const backoffMs = Math.min(300000, 1000 * (2 ** attempts))
            await repo.update('event_delivery', { id: delivery.id }, {
                status: dead ? 'dead' : 'pending',
                attempts,
                lastError: String(err.message || err).slice(0, 500),
                lastAttemptAt: new Date(),
                nextAttemptAt: dead ? null : new Date(Date.now() + backoffMs),
            })
            if (dead) counters.dead += 1
            else counters.failed += 1
            metrics?.inc('ddrive_events_failed_total', 1, { target: target.name })

            return false
        }
    }

    /** Worker tick: deliver a batch of due events. */
    const processDue = async () => {
        const due = await repo.find('event_delivery', {
            status: 'pending',
            nextAttemptAt: { lte: new Date() },
        }, { orderBy: [{ column: 'nextAttemptAt', dir: 'asc' }], limit: batchSize })
        if (!due.length) return 0
        await Promise.all(due.map((d) => deliverOne(d).catch(() => {})))

        return due.length
    }

    /** Move stale "pending" deliveries (crashed workers) back into the queue. */
    const recoverStuck = async (olderThanMs = 300000) => {
        const cutoff = new Date(Date.now() - olderThanMs)
        return repo.update('event_delivery', {
            status: 'in-flight', nextAttemptAt: { lt: cutoff },
        }, { status: 'pending', nextAttemptAt: new Date() })
    }

    const listTargets = () => repo.find('event_target', {}, { orderBy: [{ column: 'name', dir: 'asc' }] })

    const createTarget = async (input) => {
        if (!input.name || !input.url) throw new Error('event target requires a name and a url')
        return repo.insert('event_target', {
            name: input.name,
            type: input.type || 'webhook',
            url: input.url,
            secret: input.secret || null,
            events: input.events || ['*'],
            bucketId: input.bucketId || null,
            prefix: input.prefix || null,
            status: input.status || 'enabled',
            maxRetries: input.maxRetries ?? maxRetriesDefault,
            timeoutMs: input.timeoutMs || 10000,
            headers: input.headers || null,
        })
    }

    const updateTarget = (id, patch) => repo.update('event_target', { id }, patch)
    const deleteTarget = async (id) => {
        await repo.delete('event_delivery', { targetId: id })

        return repo.delete('event_target', { id })
    }

    const listDeliveries = (filters = {}) => repo.find('event_delivery', {
        ...(filters.status ? { status: filters.status } : {}),
        ...(filters.targetId ? { targetId: filters.targetId } : {}),
    }, { orderBy: [{ column: 'createdAt', dir: 'desc' }], limit: Math.min(filters.limit || 100, 500) })

    /** Requeue a dead letter (or all of them). */
    const redrive = async (id) => {
        if (id) {
            await repo.update('event_delivery', { id }, { status: 'pending', attempts: 0, nextAttemptAt: new Date() })

            return 1
        }
        const dead = await repo.find('event_delivery', { status: 'dead' })
        for (const d of dead) {
            // eslint-disable-next-line no-await-in-loop
            await repo.update('event_delivery', { id: d.id }, { status: 'pending', attempts: 0, nextAttemptAt: new Date() })
        }

        return dead.length
    }

    return {
        emit,
        subscribe,
        processDue,
        recoverStuck,
        listTargets,
        createTarget,
        updateTarget,
        deleteTarget,
        listDeliveries,
        redrive,
        toS3Record,
        counters,
        intervalMs,
    }
}

module.exports = { createEvents, S3_EVENT_NAMES }
