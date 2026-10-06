/**
 * Intelligent tiering.
 *
 * Moves object chunks between storage tiers (HOT -> COOL -> ARCHIVE) based on
 *   - age since creation
 *   - idle time (last access)
 *   - access frequency / bytes served
 *   - object size
 *
 * A tier can be a different backend (for example an S3 compatible archive
 * bucket) - see `createChunkStore` in src/core/storage - and transitions are
 * transparent to every protocol: reads just follow the chunk locator.
 */
const util = require('../lib/util')
const { errors } = require('../lib/errors')

const STORAGE_CLASS_BY_TIER = {
    HOT: 'STANDARD',
    COOL: 'STANDARD_IA',
    ARCHIVE: 'GLACIER',
}

const createTiering = (deps = {}) => {
    const {
        repo, store, objects, events, audit, logger = console,
    } = deps

    const listPolicies = (bucket) => repo.find('tiering_policy', bucket ? { bucketId: bucket.id } : {}, { orderBy: [{ column: 'createdAt', dir: 'asc' }] })

    const createPolicy = async (bucket, input) => {
        if (!input.name) throw errors.validation('Tiering policy requires a name')
        const hotToCoolDays = input.hotToCoolDays ?? 30
        const coolToArchiveDays = input.coolToArchiveDays ?? 180
        if (coolToArchiveDays < hotToCoolDays) throw errors.validation('coolToArchiveDays must be greater than or equal to hotToCoolDays')

        return repo.insert('tiering_policy', {
            bucketId: bucket ? bucket.id : null,
            name: input.name,
            enabled: input.enabled !== false,
            hotToCoolDays,
            coolToArchiveDays,
            minAccessCount: input.minAccessCount ?? 2,
            minSizeBytes: input.minSizeBytes || 0,
            targetTier: input.targetTier || null,
            intervalMinutes: input.intervalMinutes || 60,
        })
    }

    const updatePolicy = (id, patch) => repo.update('tiering_policy', { id }, patch)
    const deletePolicy = (id) => repo.delete('tiering_policy', { id })

    const daysSince = (date) => (date ? (Date.now() - new Date(date).getTime()) / 86400000 : Infinity)

    /**
     * Move a version's chunks to another tier (metadata + blobs).
     * @param {object} bucket
     * @param {object} node      directory row
     * @param {object} version   object_version row
     * @param {string} targetTier HOT|COOL|ARCHIVE
     * @param {object} [opts] { source, storageClass }
     */
    const transitionVersion = async (bucket, node, version, targetTier, opts = {}) => {
        if (!['HOT', 'COOL', 'ARCHIVE'].includes(targetTier)) throw errors.invalidArgument(`Unknown tier ${targetTier}`)
        const currentTier = version.tier || 'HOT'
        if (currentTier === targetTier) return { moved: false, tier: targetTier }
        const blocks = await repo.find('block', { versionId: version.id }, { orderBy: [{ column: 'ordinal', dir: 'asc' }] })
        let moved = 0
        const failures = []
        for (const block of blocks) {
            try {
                // eslint-disable-next-line no-await-in-loop
                const res = await store.move(block.url, targetTier)
                if (res.moved) {
                    moved += 1
                    // eslint-disable-next-line no-await-in-loop
                    await repo.update('block', { id: block.id }, {
                        url: res.locator, tier: targetTier, migratedAt: new Date(),
                    })
                }
            } catch (err) {
                // A missing tier backend must not corrupt metadata: keep the old
                // locator and report the failure.
                failures.push({ blockId: block.id, error: err.message })
                logger.warn?.({ err, blockId: block.id, targetTier }, 'tier transition failed for chunk')
            }
        }
        if (failures.length === blocks.length && blocks.length) {
            throw errors.internal(`All ${blocks.length} chunks failed to move to ${targetTier}: ${failures[0].error}`)
        }
        const storageClass = opts.storageClass || STORAGE_CLASS_BY_TIER[targetTier] || 'STANDARD'
        await repo.update('object_version', { id: version.id }, {
            tier: targetTier, storageClass, tieredAt: new Date(),
        })
        await repo.update('directory', { id: node.id }, { storageClass })
        await audit?.record({
            action: 'tiering.transition',
            actor: opts.source || 'system',
            actorType: 'system',
            resource: `arn:ddrive:s3:::${bucket.name}/${node.path}`,
            bucket: bucket.name,
            bucketId: bucket.id,
            objectKey: node.path,
            versionId: version.id,
            protocol: 'internal',
            detail: {
                from: currentTier, to: targetTier, chunksMoved: moved, failures: failures.length,
            },
        })

        return {
            moved: true, tier: targetTier, from: currentTier, chunks: moved, failures: failures.length,
        }
    }

    /**
     * Evaluate tiering policies.
     * @param {object} opts { bucket, dryRun, limit }
     */
    const run = async (opts = {}) => {
        const {
            bucket, dryRun = false, limit = 2000,
        } = opts
        const where = { enabled: true }
        if (bucket) where.bucketId = bucket.id
        const policies = await repo.find('tiering_policy', where)
        const summary = {
            ranAt: util.iso(new Date()), dryRun, policies: policies.length, evaluated: 0, transitions: 0, bytes: 0, errors: [], details: [],
        }

        for (const policy of policies) {
            const bucketRow = bucket || await repo.findOne('bucket', { id: policy.bucketId })
            if (!bucketRow) continue
            const detail = {
                policy: policy.name, bucket: bucketRow.name, toCool: 0, toArchive: 0, skipped: 0,
            }
            let candidates = 0
            // COOL candidates: hot objects that have been idle
            // eslint-disable-next-line no-await-in-loop
            const nodes = await repo.find('directory', { bucketId: bucketRow.id, type: 'file', deletedAt: null }, { limit })
            for (const node of nodes) {
                if (candidates >= limit) break
                if (policy.minSizeBytes && Number(node.size) < Number(policy.minSizeBytes)) continue
                // eslint-disable-next-line no-await-in-loop
                const version = node.latestVersionId ? await repo.findOne('object_version', { id: node.latestVersionId }) : null
                if (!version || version.isDeleteMarker) continue
                candidates += 1
                summary.evaluated += 1
                const idleDays = daysSince(node.lastAccessAt || node.createdAt)
                const ageDays = daysSince(node.createdAt)
                const accessCount = Number(node.accessCount || 0)
                const tier = version.tier || 'HOT'
                const oftenAccessed = accessCount > Number(policy.minAccessCount || 0)

                let target = null
                if (tier === 'HOT' && ageDays >= Number(policy.hotToCoolDays) && idleDays >= Number(policy.hotToCoolDays) && !oftenAccessed) {
                    target = 'COOL'
                } else if (tier === 'COOL' && ageDays >= Number(policy.coolToArchiveDays) && idleDays >= Number(policy.coolToArchiveDays)) {
                    target = policy.targetTier && policy.targetTier !== 'HOT' ? policy.targetTier : 'ARCHIVE'
                }
                if (!target) {
                    detail.skipped += 1
                    continue
                }
                if (dryRun) {
                    summary.transitions += 1
                    detail[target === 'COOL' ? 'toCool' : 'toArchive'] += 1
                    continue
                }
                try {
                    // eslint-disable-next-line no-await-in-loop
                    await transitionVersion(bucketRow, node, version, target, { source: 'tiering' })
                    summary.transitions += 1
                    summary.bytes += Number(version.size || 0)
                    detail[target === 'COOL' ? 'toCool' : 'toArchive'] += 1
                    // eslint-disable-next-line no-await-in-loop
                    await events?.emit('OBJECT_TIER_CHANGED', {
                        bucket: bucketRow, node, versionId: version.id, actor: { name: 'tiering', type: 'system' }, detail: { tier: target, policy: policy.name },
                    })
                } catch (err) {
                    summary.errors.push({ path: node.path, error: err.message })
                }
            }
            if (!dryRun) {
                // eslint-disable-next-line no-await-in-loop
                await repo.update('tiering_policy', { id: policy.id }, { lastRunAt: new Date(), lastRunSummary: detail })
            }
            summary.details.push(detail)
        }

        if (!dryRun && summary.transitions) {
            await audit?.record({
                action: 'tiering.run',
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

    /** Tier distribution report (console dashboard). */
    const report = async (bucketId) => {
        const rows = await repo.all(
            `select v."tier" as tier, count(*) as versions, coalesce(sum(v."size"), 0) as bytes
             from "object_version" v where v."isDeleteMarker" = ${repo.dialect === 'pg' ? 'false' : '0'}
             ${bucketId ? 'and v."bucketId" = ?' : ''} group by v."tier"`,
            bucketId ? [bucketId] : [],
        )

        return rows.map((r) => ({ tier: r.tier || 'HOT', versions: Number(r.versions), bytes: Number(r.bytes) }))
    }

    const start = (intervalMs = 3600000) => {
        if (intervalMs <= 0) return null
        const timer = setInterval(() => { run().catch((err) => logger.error?.({ err }, 'tiering run failed')) }, intervalMs)
        timer.unref?.()

        return timer
    }

    return {
        listPolicies,
        createPolicy,
        updatePolicy,
        deletePolicy,
        transitionVersion,
        run,
        report,
        start,
        STORAGE_CLASS_BY_TIER,
    }
}

module.exports = { createTiering, STORAGE_CLASS_BY_TIER }
