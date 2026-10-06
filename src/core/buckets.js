/**
 * Bucket service: namespaces, versioning state, object lock configuration,
 * quotas, CORS and per-bucket policy documents.
 */
const { errors } = require('../lib/errors')
const util = require('../lib/util')

const RESERVED = new Set(['ddrive', 'admin', 'api', 'webdav', 's3', 'console', 'metrics', '_internal'])
const NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/
// eslint-disable-next-line no-control-regex
const INVALID_NAME_CHARS = /[^a-z0-9.\-]/

const createBuckets = (deps) => {
    const {
        repo, crypto, events, logger,
    } = deps
    const objects = () => deps.objects

    const assertName = (name, { allowReserved = false } = {}) => {
        const value = String(name || '')
        if (!NAME_RE.test(value) || value.includes('..') || INVALID_NAME_CHARS.test(value)) {
            throw errors.invalidArgument(
                'Bucket name must be 3-63 characters, lowercase alphanumeric with dots and hyphens, and must start and end with a letter or number',
                { name: value },
            )
        }
        if (!allowReserved && RESERVED.has(value)) throw errors.invalidArgument(`Bucket name "${value}" is reserved`)
    }

    const get = async (name) => {
        const bucket = await repo.findOne('bucket', { name: util.normalizeKey(name) })
        if (!bucket) throw errors.noSuchBucket(name)

        return bucket
    }

    const exists = async (name) => repo.exists('bucket', { name: util.normalizeKey(name) })

    const list = async () => repo.find('bucket', {}, { orderBy: [{ column: 'name', dir: 'asc' }] })

    /** Create the bucket row + its root directory (the bucket id is the root dir id). */
    const create = async (name, opts = {}) => {
        assertName(name, { allowReserved: !!opts.allowReserved })
        const existing = await repo.findOne('bucket', { name })
        if (existing) {
            if (opts.idempotent && existing.ownerId === (opts.ownerId || null)) return existing
            throw errors.bucketAlreadyExists(name)
        }
        const created = await repo.transaction(async (tx) => {
            const bucket = await tx.insert('bucket', {
                name,
                region: opts.region || 'primary',
                ownerId: opts.ownerId || null,
                versioning: opts.versioning || 'off',
                objectLockEnabled: !!opts.objectLockEnabled,
                defaultRetentionMode: opts.defaultRetentionMode || null,
                defaultRetentionDays: opts.defaultRetentionDays || null,
                defaultLegalHold: !!opts.defaultLegalHold,
                defaultStorageClass: opts.defaultStorageClass || 'STANDARD',
                quotaBytes: opts.quotaBytes || null,
                tags: opts.tags || null,
                metadata: opts.metadata || null,
                cors: opts.cors || null,
            })
            await tx.insert('directory', {
                id: bucket.id,
                bucketId: bucket.id,
                parentId: null,
                name: bucket.name,
                path: '',
                depth: 0,
                type: 'directory',
                ownerId: bucket.ownerId,
                createdBy: opts.createdBy || null,
            })

            return bucket
        })
        events?.emit('BUCKET_CREATED', { bucket: created }).catch(() => {})

        return created
    }

    const update = async (name, patch) => {
        const bucket = await get(name)
        const allowed = {}
        const fields = [
            'versioning', 'defaultRetentionMode', 'defaultRetentionDays', 'defaultLegalHold',
            'defaultStorageClass', 'quotaBytes', 'tags', 'metadata', 'cors', 'ownerId', 'region',
        ]
        fields.forEach((f) => {
            if (patch[f] !== undefined) allowed[f] = patch[f]
        })
        if (allowed.versioning && !['off', 'enabled', 'suspended'].includes(allowed.versioning)) {
            throw new errors.validation('versioning must be one of off, enabled, suspended')
        }
        if (allowed.defaultRetentionDays && !bucket.objectLockEnabled && !patch.objectLockEnabled) {
            throw errors.invalidRequest('Object Lock must be enabled before setting a default retention')
        }
        if (patch.objectLockEnabled) allowed.objectLockEnabled = true
        if (!Object.keys(allowed).length) return bucket
        await repo.update('bucket', { id: bucket.id }, allowed)
        const updated = await repo.findOne('bucket', { id: bucket.id })
        events?.emit('BUCKET_UPDATED', { bucket: updated, patch: allowed }).catch(() => {})

        return updated
    }

    const remove = async (name, opts = {}) => {
        const bucket = await get(name)
        const path = opts.path ? util.normalizeKey(opts.path) : ''
        if (path) {
            // delete an object or subtree inside the bucket
            const node = await objects().getNode(bucket.id, path)
            if (!node) throw errors.noSuchKey(path)
            if (node.type === 'file') {
                await objects().deleteObject({
                    bucket, path, permanent: true, bypassGovernance: opts.bypassGovernance,
                })
            } else {
                const rows = await repo.find('directory', { bucketId: bucket.id, path: { startsWith: `${path}/` } })
                for (const row of rows.filter((r) => r.type === 'file')) {
                    // eslint-disable-next-line no-await-in-loop
                    await objects().deleteObject({
                        bucket, path: row.path, permanent: true, bypassGovernance: opts.bypassGovernance,
                    })
                }
                await repo.delete('directory', { bucketId: bucket.id, path: { startsWith: `${path}/` } })
                await repo.delete('directory', { id: node.id })
            }

            return { deleted: true, bucket: bucket.name, path }
        }

        const children = await repo.find('directory', { bucketId: bucket.id, parentId: bucket.id })
        const files = await repo.count('directory', { bucketId: bucket.id, type: 'file' })
        if ((children.length || files) && !opts.force) throw errors.bucketNotEmpty(bucket.name)
        if (opts.force) {
            const rows = await repo.find('directory', { bucketId: bucket.id })
            for (const row of rows.filter((r) => r.type === 'file')) {
                // eslint-disable-next-line no-await-in-loop
                await objects().deleteObject({
                    bucket, path: row.path, permanent: true, bypassGovernance: opts.bypassGovernance,
                })
            }
            await repo.delete('directory', { bucketId: bucket.id, path: { ne: '' } })
        }
        await repo.delete('bucket_policy', { bucketId: bucket.id })
        await repo.delete('lifecycle_rule', { bucketId: bucket.id })
        await repo.delete('tiering_policy', { bucketId: bucket.id })
        await repo.delete('bucket', { id: bucket.id })
        events?.emit('BUCKET_REMOVED', { bucket }).catch(() => {})

        return { deleted: true, bucket: bucket.name }
    }

    /** Object lock configuration (S3 PutObjectLockConfiguration). */
    const getObjectLock = async (name) => {
        const bucket = await get(name)

        return {
            objectLockEnabled: bucket.objectLockEnabled,
            mode: bucket.defaultRetentionMode,
            days: bucket.defaultRetentionDays,
            legalHold: bucket.defaultLegalHold,
        }
    }

    const setObjectLock = async (name, { enabled = true, mode, days, legalHold = false }) => {
        const bucket = await get(name)
        if (mode && !['GOVERNANCE', 'COMPLIANCE'].includes(mode)) throw errors.validation('mode must be GOVERNANCE or COMPLIANCE')
        await repo.update('bucket', { id: bucket.id }, {
            objectLockEnabled: enabled ? true : bucket.objectLockEnabled,
            defaultRetentionMode: mode || null,
            defaultRetentionDays: days === undefined ? null : Number(days),
            defaultLegalHold: !!legalHold,
        })

        return getObjectLock(name)
    }

    const getPolicy = async (name) => {
        const bucket = await get(name)
        const policy = await repo.findOne('bucket_policy', { bucketId: bucket.id })

        return policy ? policy.document : null
    }

    const setPolicy = async (name, document, actor = {}) => {
        const bucket = await get(name)
        if (document !== null && typeof document !== 'object') throw errors.validation('Policy must be a JSON document or null')
        const existing = await repo.findOne('bucket_policy', { bucketId: bucket.id })
        if (!document) {
            if (existing) await repo.delete('bucket_policy', { id: existing.id })
            events?.emit('BUCKET_POLICY_REMOVED', { bucket, actor }).catch(() => {})

            return null
        }
        if (existing) {
            await repo.update('bucket_policy', { id: existing.id }, { document, createdBy: actor.name || null })
        } else {
            await repo.insert('bucket_policy', { bucketId: bucket.id, name: `${bucket.name}-policy`, document, createdBy: actor.name || null })
        }
        events?.emit('BUCKET_POLICY_UPDATED', { bucket, document, actor }).catch(() => {})

        return document
    }

    /** Encryption / durability posture as reported by the console and health-check. */
    const posture = async (name) => {
        const bucket = await get(name)

        return {
            bucket: bucket.name,
            region: bucket.region,
            versioning: bucket.versioning,
            objectLock: {
                enabled: bucket.objectLockEnabled,
                mode: bucket.defaultRetentionMode,
                days: bucket.defaultRetentionDays,
                legalHold: bucket.defaultLegalHold,
            },
            encryption: crypto && crypto.enabled
                ? { algorithm: crypto.algorithm, keyId: crypto.keyId, envelope: 'per-object-dek' }
                : { enabled: false },
            quotaBytes: bucket.quotaBytes,
        }
    }

    return {
        assertName,
        get,
        exists,
        list,
        create,
        update,
        remove,
        getObjectLock,
        setObjectLock,
        getPolicy,
        setPolicy,
        posture,
    }
}

module.exports = { createBuckets, RESERVED, NAME_RE }
