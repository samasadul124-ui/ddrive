/**
 * Cross region replication.
 *
 * Every write produces a durable replication task per matching peer. A worker
 * drains those tasks with exponential backoff, pushing the object to the remote
 * DDrive node (or to any S3 compatible endpoint) and recording the outcome.
 * Incoming replication requests are applied through `applyIncoming()`, which
 * makes two DDrive deployments with peers pointing at each other active/active.
 *
 * Failure modes are explicit: a peer that is down, rate limited or rejecting
 * writes leaves tasks in `pending` (retry) or `failed` (DLQ) with the error,
 * visible in the console and in the `ddrive_replication_backlog` metric.
 */
const { Readable } = require('stream')
const util = require('../lib/util')
const { errors } = require('../lib/errors')
const sigv4 = require('../lib/sigv4')

const REPLICATION_VERSION = '1'

const createReplication = (deps = {}) => {
    const {
        repo, objects, store, events, audit, crypto, logger = console, config = {},
    } = deps
    const regionName = config.region || 'primary'
    const nodeId = config.nodeId || `node-${util.randomHex(4)}`
    const maxAttempts = config.maxAttempts || 8
    const batchSize = config.batchSize || 10

    // ------------------------------------------------------------------
    // Peer CRUD
    // ------------------------------------------------------------------
    const listPeers = () => repo.find('replication_peer', {}, { orderBy: [{ column: 'name', dir: 'asc' }] })

    const createPeer = async (input) => {
        if (!input.name || !input.endpoint) throw errors.validation('Replication peer requires a name and endpoint')
        if (!input.accessKeyId || !input.secret) throw errors.validation('Replication peer requires accessKeyId and secret')
        const encrypted = await crypto.encryptSecret(String(input.secret))
        const peer = await repo.insert('replication_peer', {
            name: input.name,
            endpoint: String(input.endpoint).replace(/\/$/, ''),
            region: input.region || null,
            bucket: input.bucket || null,
            accessKeyId: input.accessKeyId,
            secretEnc: encrypted.value,
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            keyId: encrypted.keyId,
            direction: input.direction || 'outbound',
            prefix: input.prefix || null,
            status: input.status || 'enabled',
            verifyTls: input.verifyTls !== false,
            mode: input.mode || 'ddrive',
        })
        await audit?.record({
            action: 'replication.peer.create',
            actor: 'admin',
            actorType: 'user',
            resource: `peer:${peer.name}`,
            protocol: 'internal',
            detail: { endpoint: peer.endpoint, bucket: peer.bucket, direction: peer.direction },
        })

        return peer
    }

    const updatePeer = async (name, patch) => {
        const update = { ...patch }
        if (patch.secret) {
            const encrypted = await crypto.encryptSecret(String(patch.secret))
            update.secretEnc = encrypted.value
            update.iv = encrypted.iv
            update.authTag = encrypted.authTag
            update.keyId = encrypted.keyId
            delete update.secret
        }

        return repo.update('replication_peer', { name }, update)
    }

    const deletePeer = async (name) => {
        const peer = await repo.findOne('replication_peer', { name })
        if (!peer) throw errors.validation(`Peer ${name} does not exist`)
        await repo.delete('replication_task', { peerId: peer.id })
        await repo.delete('replication_peer', { id: peer.id })

        return true
    }

    const peerSecret = (peer) => crypto.decryptSecret({ value: peer.secretEnc, iv: peer.iv, authTag: peer.authTag })

    // ------------------------------------------------------------------
    // Outbound
    // ------------------------------------------------------------------
    const matchingPeers = async (bucket, key) => {
        const peers = await repo.find('replication_peer', { status: 'enabled' })
        return peers.filter((peer) => {
            if (peer.direction === 'inbound') return false
            if (peer.bucket && peer.bucket !== bucket.name) return false
            if (peer.prefix && !String(key || '').startsWith(peer.prefix)) return false

            return true
        })
    }

    const enqueue = async ({
        bucket, node, versionId, op = 'PUT', key,
    }) => {
        const targetKey = node ? node.path : (key || '')
        const peers = await matchingPeers(bucket, targetKey)
        if (!peers.length) return 0
        const version = versionId ? await repo.findOne('object_version', { id: versionId }) : null
        await repo.insertMany('replication_task', peers.map((peer) => ({
            peerId: peer.id,
            objectId: node ? node.id : null,
            versionId: versionId || null,
            bucketId: bucket.id,
            path: targetKey || null,
            op,
            status: 'pending',
            attempts: 0,
            sizeBytes: version ? version.size : 0,
            checksum: version ? version.checksum : null,
            nextAttemptAt: new Date(),
        })))
        await repo.update('directory', { id: node ? node.id : undefined }, { replicationStatus: 'pending' }).catch(() => {})

        return peers.length
    }

    const init = () => {
        if (!events) return () => {}
        const unsubscribe = events.subscribe(async (type, payload) => {
            const { bucket, node, versionId } = payload || {}
            if (!bucket || !node) return
            if (type === 'OBJECT_CREATED') await enqueue({ bucket, node, versionId, op: 'PUT' })
            if (type === 'OBJECT_MOVED' || type === 'OBJECT_COPIED') await enqueue({ bucket, node, versionId, op: 'PUT' })
            if (type === 'OBJECT_REMOVED' || type === 'OBJECT_DELETE_MARKER_CREATED') {
                await enqueue({
                    bucket, node, versionId, op: 'DELETE', key: node?.path,
                })
            }
            if (type === 'OBJECT_METADATA_UPDATED' || type === 'OBJECT_TAGGING') await enqueue({ bucket, node, versionId, op: 'META' })
        })

        return unsubscribe
    }

    /** Push one version to one peer. */
    const replicateVersion = async (peer, task) => {
        const bucket = await repo.findOne('bucket', { id: task.bucketId })
        if (!bucket) throw errors.internal('source bucket no longer exists')
        let node = task.objectId ? await repo.findOne('directory', { id: task.objectId }) : null
        if (!node && task.op === 'DELETE') {
            // the row is already gone (permanent delete) - the path stored on
            // the task is all the peer needs to drop its copy
            node = { id: task.objectId, path: task.path, bucketId: bucket.id }
        }
        if (!node) throw errors.internal('source object no longer exists')

        if (task.op === 'DELETE') {
            await sendDelete(peer, bucket, node)

            return { bytes: 0 }
        }
        const version = task.versionId
            ? await repo.findOne('object_version', { id: task.versionId })
            : await repo.findOne('object_version', { id: node.latestVersionId })
        if (!version) throw errors.internal('source version no longer exists')
        if (version.isDeleteMarker) {
            await sendDelete(peer, bucket, node)

            return { bytes: 0 }
        }
        const { stream } = await objects.stream(version)
        const size = await sendObject(peer, bucket, node, version, stream)

        return { bytes: size }
    }

    const metaFor = (bucket, node, version, op = 'PUT') => ({
        op,
        key: node.path,
        bucket: bucket.name,
        size: version ? Number(version.size) : 0,
        contentType: version ? version.contentType : null,
        metadata: version ? version.metadata : null,
        tags: version ? version.tags : null,
        storageClass: version ? version.storageClass : null,
        checksum: version ? version.checksum : null,
        etag: version ? version.etag : null,
        versionNumber: version ? version.versionNumber : null,
        sourceRegion: regionName,
        sourceNode: nodeId,
        retentionMode: version ? version.retentionMode : null,
        retainUntil: version ? util.iso(version.retainUntil) : null,
        legalHold: version ? !!version.legalHold : false,
    })

    const sendObject = async (peer, bucket, node, version, stream) => {
        const meta = metaFor(bucket, node, version, 'PUT')
        if (peer.mode === 's3') return sendS3Object(peer, meta, stream)
        const metaB64 = Buffer.from(JSON.stringify(meta)).toString('base64')
        const body = await util.streamToBuffer(stream)
        const secret = await peerSecret(peer)
        const timestamp = Date.now().toString()
        const signature = util.hmacSha256(secret, `${timestamp}\n${metaB64}\n${util.sha256(body)}`)
        const res = await fetch(`${peer.endpoint}/_internal/replication/objects`, {
            method: 'POST',
            headers: {
                'content-type': 'application/octet-stream',
                'x-ddrive-version': REPLICATION_VERSION,
                'x-ddrive-peer': peer.name,
                'x-ddrive-meta': metaB64,
                'x-ddrive-timestamp': timestamp,
                'x-ddrive-signature': signature,
                'x-ddrive-access-key': peer.accessKeyId,
                'content-length': String(body.length),
            },
            body,
            signal: AbortSignal.timeout(config.timeoutMs || 300000),
        })
        if (!res.ok) {
            const text = await res.text().catch(() => '')
            throw errors.internal(`peer ${peer.name} rejected replication (${res.status}) ${text.slice(0, 200)}`)
        }

        return body.length
    }

    const sendDelete = async (peer, bucket, node) => {
        if (peer.mode === 's3') {
            const url = new URL(peer.endpoint)
            const key = `${peer.bucket || bucket.name}/${node.path}`.split('/').map((p) => encodeURIComponent(p)).join('/')
            const target = `${url.origin}/${key}`
            const headers = sigv4.signRequest({ method: 'DELETE', url: target }, { accessKeyId: peer.accessKeyId, secretAccessKey: await peerSecret(peer) }, { region: peer.region || 'us-east-1', service: 's3' })
            const res = await fetch(target, { method: 'DELETE', headers, signal: AbortSignal.timeout(60000) })
            if (!res.ok && res.status !== 404) throw errors.internal(`S3 peer delete failed (${res.status})`)

            return
        }
        const secret = await peerSecret(peer)
        const metaB64 = Buffer.from(JSON.stringify(metaFor(bucket, node, null, 'DELETE'))).toString('base64')
        const timestamp = Date.now().toString()
        const signature = util.hmacSha256(secret, `${timestamp}\n${metaB64}\n${util.sha256('')}`)
        const res = await fetch(`${peer.endpoint}/_internal/replication/objects`, {
            method: 'DELETE',
            headers: {
                'x-ddrive-peer': peer.name,
                'x-ddrive-meta': metaB64,
                'x-ddrive-timestamp': timestamp,
                'x-ddrive-signature': signature,
                'x-ddrive-access-key': peer.accessKeyId,
            },
            signal: AbortSignal.timeout(60000),
        })
        if (!res.ok && res.status !== 404) throw errors.internal(`peer delete failed (${res.status})`)
    }

    const sendS3Object = async (peer, meta, stream) => {
        const url = new URL(peer.endpoint)
        const key = `${peer.bucket || meta.bucket}/${meta.key}`.split('/').map((p) => encodeURIComponent(p)).join('/')
        const target = `${url.origin}/${key}`
        const body = await util.streamToBuffer(stream)
        const headers = sigv4.signRequest({
            method: 'PUT',
            url: target,
            headers: {
                'content-type': meta.contentType || 'application/octet-stream',
                'content-length': String(body.length),
                'x-amz-meta-ddrive-checksum': meta.checksum || '',
                'x-amz-meta-ddrive-region': regionName,
            },
            body,
        }, { accessKeyId: peer.accessKeyId, secretAccessKey: await peerSecret(peer) }, { region: peer.region || 'us-east-1', service: 's3' })
        const res = await fetch(target, { method: 'PUT', headers, body, signal: AbortSignal.timeout(config.timeoutMs || 300000) })
        if (!res.ok) {
            const text = await res.text().catch(() => '')
            throw errors.internal(`S3 peer PUT failed (${res.status}) ${text.slice(0, 200)}`)
        }

        return body.length
    }

    // ------------------------------------------------------------------
    // Worker
    // ------------------------------------------------------------------
    const processDue = async (limit = batchSize) => {
        const due = await repo.find('replication_task', {
            status: 'pending',
            nextAttemptAt: { lte: new Date() },
        }, { orderBy: [{ column: 'nextAttemptAt', dir: 'asc' }], limit })
        if (!due.length) return 0
        for (const task of due) {
            const peer = await repo.findOne('replication_peer', { id: task.peerId })
            if (!peer || peer.status !== 'enabled') {
                // eslint-disable-next-line no-await-in-loop
                await repo.update('replication_task', { id: task.id }, { status: 'failed', lastError: 'peer disabled or missing' })
                continue
            }
            // eslint-disable-next-line no-await-in-loop
            await repo.update('replication_task', { id: task.id }, { status: 'in-flight' })
            try {
                // eslint-disable-next-line no-await-in-loop
                const res = await replicateVersion(peer, task)
                // eslint-disable-next-line no-await-in-loop
                await repo.update('replication_task', { id: task.id }, {
                    status: 'done', attempts: Number(task.attempts) + 1, completedAt: new Date(), lastError: null,
                })
                // eslint-disable-next-line no-await-in-loop
                await repo.update('replication_peer', { id: peer.id }, { lastSyncAt: new Date() })
                if (task.objectId) {
                    // eslint-disable-next-line no-await-in-loop
                    await repo.update('directory', { id: task.objectId }, { replicationStatus: 'replicated' }).catch(() => {})
                    // eslint-disable-next-line no-await-in-loop
                    await repo.update('object_version', { id: task.versionId || undefined }, { replicationStatus: 'replicated' }).catch(() => {})
                }
                // eslint-disable-next-line no-await-in-loop
                await audit?.record({
                    action: 'replication.completed',
                    actor: 'system',
                    actorType: 'system',
                    resource: `peer:${peer.name}`,
                    bucket: task.bucketId ? (await repo.findOne('bucket', { id: task.bucketId }))?.name : null,
                    objectKey: null,
                    protocol: 'internal',
                    detail: { bytes: res.bytes, op: task.op, taskId: task.id },
                })
                // eslint-disable-next-line no-await-in-loop
                await events?.emit('REPLICATION_COMPLETED', {
                    detail: { peer: peer.name, bytes: res.bytes, op: task.op },
                })
            } catch (err) {
                const attempts = Number(task.attempts) + 1
                // A task whose source bucket is gone can never succeed, however
                // often it is retried: retire it now instead of backing off.
                const bucketGone = task.bucketId
                    ? !(await repo.findOne('bucket', { id: task.bucketId }))
                    : false
                const dead = attempts >= maxAttempts || bucketGone
                // eslint-disable-next-line no-await-in-loop
                await repo.update('replication_task', { id: task.id }, {
                    status: dead ? 'failed' : 'pending',
                    attempts,
                    lastError: bucketGone ? 'source bucket was deleted' : String(err.message || err).slice(0, 500),
                    nextAttemptAt: dead ? null : new Date(Date.now() + Math.min(900000, 2000 * (2 ** attempts))),
                })
                if (task.objectId) {
                    // eslint-disable-next-line no-await-in-loop
                    await repo.update('directory', { id: task.objectId }, { replicationStatus: dead ? 'failed' : 'pending' }).catch(() => {})
                }
                logger.warn?.({ err, peer: peer.name, taskId: task.id }, 'replication task failed')
                if (dead) {
                    // eslint-disable-next-line no-await-in-loop
                    await events?.emit('REPLICATION_FAILED', { detail: { peer: peer.name, taskId: task.id, error: err.message } })
                }
            }
        }

        return due.length
    }

    /** Re-enqueue every latest version in scope (initial sync / disaster recovery). */
    const backfill = async (peerName, opts = {}) => {
        const peer = await repo.findOne('replication_peer', { name: peerName })
        if (!peer) throw errors.validation(`Peer ${peerName} does not exist`)
        // A peer that is scoped to one bucket must never be sent the others.
        let scopeId = opts.bucketId || null
        if (!scopeId && peer.bucket) {
            const scoped = await repo.findOne('bucket', { name: peer.bucket })
            if (!scoped) return { queued: 0, scanned: 0 }
            scopeId = scoped.id
        }
        const where = { type: 'file', deletedAt: null }
        if (scopeId) where.bucketId = scopeId
        if (peer.prefix) where.path = { startsWith: peer.prefix }
        const nodes = await repo.find('directory', where, { limit: opts.limit || 10000 })
        let queued = 0
        for (const node of nodes) {
            // eslint-disable-next-line no-await-in-loop
            const existing = await repo.findOne('replication_task', { peerId: peer.id, objectId: node.id, op: 'PUT' })
            if (existing) continue
            // eslint-disable-next-line no-await-in-loop
            await repo.insert('replication_task', {
                peerId: peer.id,
                objectId: node.id,
                versionId: node.latestVersionId,
                bucketId: node.bucketId,
                op: 'PUT',
                status: 'pending',
                attempts: 0,
                sizeBytes: node.size,
                checksum: node.checksum,
                nextAttemptAt: new Date(),
                priority: 1,
            })
            queued += 1
        }
        await audit?.record({
            action: 'replication.backfill',
            actor: opts.actor?.name || 'admin',
            actorType: 'user',
            resource: `peer:${peer.name}`,
            protocol: 'internal',
            detail: { queued, bucket: opts.bucketId || null },
        })

        return { queued, scanned: nodes.length }
    }

    /** Connectivity + credential probe. */
    const testPeer = async (peerName) => {
        const peer = await repo.findOne('replication_peer', { name: peerName })
        if (!peer) throw errors.validation(`Peer ${peerName} does not exist`)
        const started = Date.now()
        try {
            if (peer.mode === 's3') {
                const url = new URL(peer.endpoint)
                const target = `${url.origin}/${peer.bucket || ''}?list-type=2&max-keys=1`
                const headers = sigv4.signRequest({ method: 'GET', url: target }, { accessKeyId: peer.accessKeyId, secretAccessKey: await peerSecret(peer) }, { region: peer.region || 'us-east-1', service: 's3' })
                const res = await fetch(target, { method: 'GET', headers, signal: AbortSignal.timeout(15000) })

                return { ok: res.ok, status: res.status, latencyMs: Date.now() - started, mode: 's3' }
            }
            const res = await fetch(`${peer.endpoint}/_internal/replication/health`, {
                headers: { 'x-ddrive-access-key': peer.accessKeyId },
                signal: AbortSignal.timeout(15000),
            })
            const json = await res.json().catch(() => ({}))

            return {
                ok: res.ok, status: res.status, latencyMs: Date.now() - started, mode: 'ddrive', peer: json,
            }
        } catch (err) {
            return {
                ok: false, error: err.message, latencyMs: Date.now() - started, mode: peer.mode,
            }
        }
    }

    // ------------------------------------------------------------------
    // Inbound (the receiving side of replication)
    // ------------------------------------------------------------------
    /**
     * Verify and apply an inbound replicated object.
     * @param {object} req { headers, body (Buffer), peerName }
     */
    const verifyIncoming = async (headers, body) => {
        const peerName = headers['x-ddrive-peer']
        const accessKeyId = headers['x-ddrive-access-key']
        const metaB64 = headers['x-ddrive-meta']
        const timestamp = headers['x-ddrive-timestamp']
        const signature = headers['x-ddrive-signature']
        if (!peerName || !metaB64 || !timestamp || !signature) throw errors.accessDenied('Missing replication headers')
        const peer = await repo.findOne('replication_peer', { name: peerName })
        if (!peer || peer.status !== 'enabled') throw errors.accessDenied(`Unknown replication peer ${peerName}`)
        if (accessKeyId && peer.accessKeyId !== accessKeyId) throw errors.accessDenied('Replication access key mismatch')
        const skew = Math.abs(Date.now() - Number(timestamp))
        if (!Number.isFinite(skew) || skew > 900000) throw errors.accessDenied('Replication request timestamp outside the allowed window')
        const secret = await peerSecret(peer)
        const expected = util.hmacSha256(secret, `${timestamp}\n${metaB64}\n${util.sha256(body || Buffer.alloc(0))}`)
        if (!util.timingSafeEqual(expected, signature)) throw errors.accessDenied('Invalid replication signature')
        let meta
        try {
            meta = JSON.parse(Buffer.from(metaB64, 'base64').toString())
        } catch {
            throw errors.validation('Malformed replication metadata')
        }

        return { peer, meta }
    }

    /**
     * Apply an inbound object (idempotent: skips when the checksum already
     * matches the current version).
     */
    const applyIncoming = async (headers, body) => {
        const { peer, meta } = await verifyIncoming(headers, body)
        const bucketName = meta.bucket
        let bucket = await repo.findOne('bucket', { name: bucketName })
        if (!bucket) {
            bucket = await deps.buckets.create(bucketName, {
                region: meta.sourceRegion || regionName,
                createdBy: `replication:${peer.name}`,
            })
        }
        const existing = await objects.getNode(bucket.id, meta.key)
        if (meta.op === 'DELETE') {
            if (!existing) return { applied: false, reason: 'already absent' }
            await objects.deleteObject({
                bucket,
                path: meta.key,
                actor: { name: `replication:${peer.name}`, type: 'system', protocol: 'internal' },
            })

            return { applied: true, op: 'DELETE' }
        }
        if (existing && meta.checksum && existing.checksum === meta.checksum) {
            return { applied: false, reason: 'already replicated', versionId: existing.latestVersionId }
        }
        const result = await objects.putObject({
            bucket,
            path: meta.key,
            stream: Readable.from([body || Buffer.alloc(0)]),
            contentType: meta.contentType,
            metadata: { ...(meta.metadata || {}), 'ddrive-replication-source': peer.name, 'ddrive-replication-region': meta.sourceRegion || null },
            tags: meta.tags,
            storageClass: meta.storageClass,
            retentionMode: meta.retentionMode,
            retainUntil: meta.retainUntil,
            legalHold: meta.legalHold,
            actor: { name: `replication:${peer.name}`, type: 'system', protocol: 'internal' },
        })
        await audit?.record({
            action: 'replication.applied',
            actor: `replication:${peer.name}`,
            actorType: 'system',
            resource: `arn:ddrive:s3:::${bucketName}/${meta.key}`,
            bucket: bucketName,
            objectKey: meta.key,
            versionId: result.versionId,
            protocol: 'internal',
            detail: { bytes: result.size, checksum: meta.checksum, sourceRegion: meta.sourceRegion },
        })

        return {
            applied: true, op: 'PUT', versionId: result.versionId, etag: result.etag, size: result.size,
        }
    }

    const stats = async () => {
        const rows = await repo.all('select "status", count(*) as count from "replication_task" group by "status"')
        const peers = await listPeers()
        const pendingFor = await repo.all('select "peerId", count(*) as count from "replication_task" where "status" in (\'pending\', \'in-flight\') group by "peerId"')
        const pendingMap = new Map(pendingFor.map((r) => [r.peerId, Number(r.count)]))

        return {
            byStatus: Object.fromEntries(rows.map((r) => [r.status, Number(r.count)])),
            peers: peers.map((p) => ({
                name: p.name, status: p.status, region: p.region, mode: p.mode || 'ddrive', backlog: pendingMap.get(p.id) || 0, lastSyncAt: p.lastSyncAt,
            })),
        }
    }

    const start = (intervalMs = 3000) => {
        if (intervalMs <= 0) return null
        const timer = setInterval(() => { processDue().catch((err) => logger.error?.({ err }, 'replication worker failed')) }, intervalMs)
        timer.unref?.()

        return timer
    }

    return {
        init,
        listPeers,
        createPeer,
        updatePeer,
        deletePeer,
        testPeer,
        enqueue,
        processDue,
        backfill,
        verifyIncoming,
        applyIncoming,
        stats,
        start,
        regionName,
        nodeId,
    }
}

module.exports = { createReplication }
