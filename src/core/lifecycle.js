/**
 * Lifecycle engine.
 *
 * Implements the S3 lifecycle model on top of the object service:
 *   - transitions            (storage class / tier changes after N days)
 *   - expiration             (delete current versions after N days)
 *   - noncurrent expiration  (delete old versions after N days / keep last N)
 *   - delete marker cleanup  (expire expired object delete markers)
 *   - incomplete multipart   (abort uploads older than N days)
 *
 * Object Lock and legal holds always win: locked versions are skipped and
 * reported in the run summary instead of being deleted.
 */
const util = require('../lib/util')
const { errors } = require('../lib/errors')
const { isLockedNow } = require('./objects')

const TIER_BY_STORAGE_CLASS = {
    STANDARD: 'HOT',
    STANDARD_IA: 'COOL',
    ONEZONE_IA: 'COOL',
    INTELLIGENT_TIERING: 'HOT',
    GLACIER: 'ARCHIVE',
    GLACIER_IR: 'ARCHIVE',
    DEEP_ARCHIVE: 'ARCHIVE',
}

const createLifecycle = (deps = {}) => {
    const {
        repo, objects, events, audit, tagger, logger = console, tiering,
    } = deps

    // ------------------------------------------------------------------
    // Rule CRUD
    // ------------------------------------------------------------------
    const listRules = (bucket) => repo.find('lifecycle_rule', bucket ? { bucketId: bucket.id } : {}, { orderBy: [{ column: 'priority', dir: 'asc' }] })

    const validate = (input) => {
        if (!input.name) throw errors.validation('Lifecycle rule requires a name')
        const transitions = (input.transitions || []).map((t) => {
            if (!t.days && t.days !== 0) throw errors.validation('Transition requires days')
            const storageClass = t.storageClass || 'GLACIER'
            if (!TIER_BY_STORAGE_CLASS[storageClass]) throw errors.validation(`Unknown storage class ${storageClass}`)

            return { days: Number(t.days), storageClass, tier: t.tier || TIER_BY_STORAGE_CLASS[storageClass] }
        })
        transitions.sort((a, b) => a.days - b.days)

        return {
            prefix: input.prefix || null,
            tagKey: input.tagKey || null,
            tagValue: input.tagValue || null,
            minObjectSize: input.minObjectSize ? Number(input.minObjectSize) : null,
            transitions,
            expirationDays: input.expirationDays === undefined || input.expirationDays === null ? null : Number(input.expirationDays),
            expireDeleteMarkers: !!input.expireDeleteMarkers,
            noncurrentVersionExpirationDays: input.noncurrentVersionExpirationDays ? Number(input.noncurrentVersionExpirationDays) : null,
            noncurrentVersionsToRetain: input.noncurrentVersionsToRetain === undefined || input.noncurrentVersionsToRetain === null
                ? null
                : Number(input.noncurrentVersionsToRetain),
            abortIncompleteMultipartDays: input.abortIncompleteMultipartDays ? Number(input.abortIncompleteMultipartDays) : null,
            status: input.status === 'Disabled' ? 'Disabled' : 'Enabled',
            priority: input.priority ?? 10,
        }
    }

    const createRule = async (bucket, input, actor = {}) => {
        const data = validate(input)

        return repo.insert('lifecycle_rule', {
            bucketId: bucket ? bucket.id : null, name: input.name, createdBy: actor.name || null, ...data,
        })
    }

    const updateRule = async (id, input) => {
        const existing = await repo.findOne('lifecycle_rule', { id })
        if (!existing) throw errors.validation(`Lifecycle rule ${id} does not exist`)
        const data = validate({ ...existing, ...input, name: input.name || existing.name })

        return repo.update('lifecycle_rule', { id }, data)
    }

    const deleteRule = async (id) => repo.delete('lifecycle_rule', { id })

    // ------------------------------------------------------------------
    // Evaluation
    // ------------------------------------------------------------------
    const matchesRule = (rule, node) => {
        if (rule.prefix && !String(node.path).startsWith(rule.prefix)) return false
        if (rule.tagKey) {
            const tags = node.tags || {}
            if (tags[rule.tagKey] === undefined) return false
            if (rule.tagValue && tags[rule.tagKey] !== rule.tagValue) return false
        }
        if (rule.minObjectSize && Number(node.size) < Number(rule.minObjectSize)) return false

        return true
    }

    const daysSince = (date) => (Date.now() - new Date(date).getTime()) / 86400000

    /**
     * Run lifecycle rules.
     * @param {object} opts { bucket, dryRun, ruleId }
     */
    const run = async (opts = {}) => {
        const { bucket, dryRun = false, ruleId } = opts
        const where = {}
        if (bucket) where.bucketId = bucket.id
        if (ruleId) where.id = ruleId
        const rules = await repo.find('lifecycle_rule', { ...where, status: 'Enabled' }, { orderBy: [{ column: 'priority', dir: 'asc' }] })
        const summary = {
            ranAt: util.iso(new Date()),
            dryRun,
            rules: rules.length,
            transitions: 0,
            expired: 0,
            expiredVersions: 0,
            deleteMarkersRemoved: 0,
            abortedUploads: 0,
            skippedLocked: 0,
            errors: [],
            details: [],
        }

        for (const rule of rules) {
            // eslint-disable-next-line no-await-in-loop
            const ruleSummary = await runRule(rule, { dryRun, summary, bucket })
            summary.details.push(ruleSummary)
            if (!dryRun) {
                // eslint-disable-next-line no-await-in-loop
                await repo.update('lifecycle_rule', { id: rule.id }, { lastRunAt: new Date(), lastRunSummary: ruleSummary })
            }
        }

        if (!dryRun) {
            await audit?.record({
                action: 'lifecycle.run',
                actor: 'system',
                actorType: 'system',
                resource: bucket ? `arn:ddrive:s3:::${bucket.name}` : 'arn:ddrive:s3:::',
                bucket: bucket?.name,
                protocol: 'internal',
                detail: { ...summary, details: undefined },
            })
        }

        return summary
    }

    const runRule = async (rule, { dryRun, summary, bucket: scopedBucket }) => {
        const bucketRow = scopedBucket || await repo.findOne('bucket', { id: rule.bucketId })
        if (!bucketRow) return { rule: rule.name, skipped: 'bucket missing' }
        const result = {
            rule: rule.name, bucket: bucketRow.name, transitions: 0, expired: 0, expiredVersions: 0, deleteMarkersRemoved: 0, skippedLocked: 0,
        }
        const where = { bucketId: bucketRow.id, type: 'file' }
        if (rule.prefix) where.path = { startsWith: rule.prefix }
        const nodes = await repo.find('directory', where, { limit: 100000 })

        for (const node of nodes.filter((n) => matchesRule(rule, n) && !n.deletedAt)) {
            // --------------------------------------------------------
            // Transitions + expiration for the current version
            // --------------------------------------------------------
            const ageDays = daysSince(node.createdAt)
            const version = node.latestVersionId ? await repo.findOne('object_version', { id: node.latestVersionId }) : null

            if (rule.expirationDays !== null && ageDays >= rule.expirationDays) {
                const locked = isLockedNow(version)
                if (locked) {
                    result.skippedLocked += 1
                    summary.skippedLocked += 1
                } else if (dryRun) {
                    result.expired += 1
                } else {
                    try {
                        // eslint-disable-next-line no-await-in-loop
                        await objects.deleteObject({
                            bucket: bucketRow,
                            path: node.path,
                            actor: { name: 'lifecycle', type: 'system', protocol: 'internal' },
                        })
                        result.expired += 1
                        summary.expired += 1
                        // eslint-disable-next-line no-await-in-loop
                        await events?.emit('LIFECYCLE_EXPIRATION', {
                            bucket: bucketRow, node, actor: { name: 'lifecycle', type: 'system' }, detail: { rule: rule.name, ageDays },
                        })
                    } catch (err) {
                        summary.errors.push({ path: node.path, error: err.message })
                    }
                }
                continue
            }

            const transition = [...(rule.transitions || [])].reverse().find((t) => ageDays >= t.days)
            if (transition && version) {
                const currentTier = version.tier || 'HOT'
                if (currentTier !== transition.tier) {
                    if (dryRun) {
                        result.transitions += 1
                        summary.transitions += 1
                    } else {
                        try {
                            // eslint-disable-next-line no-await-in-loop
                            await applyTransition(bucketRow, node, version, transition)
                            result.transitions += 1
                            summary.transitions += 1
                        } catch (err) {
                            summary.errors.push({ path: node.path, error: err.message })
                        }
                    }
                }
            }
        }

        // ------------------------------------------------------------
        // Noncurrent version expiration
        // ------------------------------------------------------------
        if (rule.noncurrentVersionExpirationDays || rule.noncurrentVersionsToRetain !== null) {
            const objectIds = nodes.map((n) => n.id)
            for (const batch of util.chunkArray(objectIds, 200)) {
                // eslint-disable-next-line no-await-in-loop
                const versions = await repo.find('object_version', { objectId: { in: batch }, isLatest: false }, {
                    orderBy: [{ column: 'objectId', dir: 'asc' }, { column: 'versionNumber', dir: 'desc' }],
                })
                const byObject = new Map()
                versions.forEach((v) => {
                    const list = byObject.get(v.objectId) || []
                    list.push(v)
                    byObject.set(v.objectId, list)
                })
                for (const [objectId, list] of byObject.entries()) {
                    const node = nodes.find((n) => n.id === objectId)
                    const keep = rule.noncurrentVersionsToRetain === null ? 0 : Number(rule.noncurrentVersionsToRetain)
                    const candidates = list.slice(keep).filter((v) => {
                        if (!rule.noncurrentVersionExpirationDays) return true

                        return daysSince(v.createdAt) >= Number(rule.noncurrentVersionExpirationDays)
                    })
                    for (const version of candidates) {
                        if (version.legalHold || (version.retainUntil && new Date(version.retainUntil).getTime() > Date.now())) {
                            result.skippedLocked += 1
                            summary.skippedLocked += 1
                            continue
                        }
                        if (dryRun) {
                            result.expiredVersions += 1
                            summary.expiredVersions += 1
                            continue
                        }
                        try {
                            // eslint-disable-next-line no-await-in-loop
                            await objects.deleteObject({
                                bucket: bucketRow,
                                path: node.path,
                                versionId: version.id,
                                bypassGovernance: false,
                                actor: { name: 'lifecycle', type: 'system', protocol: 'internal' },
                            })
                            result.expiredVersions += 1
                            summary.expiredVersions += 1
                            // eslint-disable-next-line no-await-in-loop
                            await events?.emit('LIFECYCLE_EXPIRATION', {
                                bucket: bucketRow, node, versionId: version.id, actor: { name: 'lifecycle', type: 'system' }, detail: { rule: rule.name, version: true },
                            })
                        } catch (err) {
                            summary.errors.push({ path: node.path, versionId: version.id, error: err.message })
                        }
                    }
                }
            }
        }

        // ------------------------------------------------------------
        // Expired delete markers
        // ------------------------------------------------------------
        if (rule.expireDeleteMarkers) {
            const markers = await repo.find('object_version', { bucketId: bucketRow.id, isDeleteMarker: true, isLatest: true }, { limit: 5000 })
            for (const marker of markers) {
                if (daysSince(marker.createdAt) < (rule.expirationDays || 1)) continue
                if (dryRun) {
                    result.deleteMarkersRemoved += 1
                    summary.deleteMarkersRemoved += 1
                    continue
                }
                // eslint-disable-next-line no-await-in-loop
                await repo.delete('object_version', { id: marker.id }).catch(() => {})
                // eslint-disable-next-line no-await-in-loop
                await objects.deleteObject({
                    bucket: bucketRow, path: marker.path, versionId: marker.id, actor: { name: 'lifecycle', type: 'system' },
                }).catch(() => {})
                result.deleteMarkersRemoved += 1
                summary.deleteMarkersRemoved += 1
            }
        }

        // ------------------------------------------------------------
        // Abort incomplete multipart uploads
        // ------------------------------------------------------------
        if (rule.abortIncompleteMultipartDays) {
            const cutoff = util.addDays(new Date(), -rule.abortIncompleteMultipartDays)
            const uploads = await repo.find('multipart_upload', { bucketId: bucketRow.id, status: 'in-progress', createdAt: { lt: cutoff } })
            for (const upload of uploads) {
                if (dryRun) {
                    result.abortedUploads += 1
                    summary.abortedUploads += 1
                    continue
                }
                // eslint-disable-next-line no-await-in-loop
                await objects.abortMultipart(bucketRow, upload.id).catch((err) => summary.errors.push({ uploadId: upload.id, error: err.message }))
                result.abortedUploads += 1
                summary.abortedUploads += 1
            }
        }

        return result
    }

    const applyTransition = async (bucket, node, version, transition) => {
        if (tiering && tiering.transitionVersion) {
            await tiering.transitionVersion(bucket, node, version, transition.tier, { source: 'lifecycle', storageClass: transition.storageClass })
        } else {
            await repo.update('object_version', { id: version.id }, { tier: transition.tier, storageClass: transition.storageClass, tieredAt: new Date() })
            await repo.update('directory', { id: node.id }, { storageClass: transition.storageClass })
        }
        await events?.emit('LIFECYCLE_TRANSITION', {
            bucket,
            node,
            versionId: version.id,
            actor: { name: 'lifecycle', type: 'system' },
            detail: { tier: transition.tier, storageClass: transition.storageClass, rule: 'lifecycle' },
        })
    }

    const start = (intervalMs = 900000) => {
        if (intervalMs <= 0) return null
        const timer = setInterval(() => {
            run().catch((err) => logger.error?.({ err }, 'lifecycle run failed'))
        }, intervalMs)
        timer.unref?.()

        return timer
    }

    return {
        listRules,
        createRule,
        updateRule,
        deleteRule,
        run,
        runRule,
        start,
        TIER_BY_STORAGE_CLASS,
    }
}

module.exports = { createLifecycle, TIER_BY_STORAGE_CLASS }
