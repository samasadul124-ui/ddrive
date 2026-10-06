/**
 * Object service: the single source of truth for reading and writing data.
 *
 * Every protocol (REST, WebDAV, S3, console) funnels through this service so
 * that versioning, object locks, encryption, quotas, tagging, events and
 * replication behave identically no matter how a byte arrived.
 *
 * Data model refresher
 *   bucket            namespace (S3 bucket / WebDAV top level collection)
 *   directory         tree node: `type=file` for objects, `type=directory` for
 *                     prefixes, with a denormalised `path` for S3 style listing
 *   object_version    immutable version record (S3 versionId = this row id)
 *   block             one stored chunk of a version (locator + IV + key id)
 */
const { Readable, PassThrough } = require('stream')
const { randomUUID } = require('crypto')
const { errors, StorageError } = require('../lib/errors')
const util = require('../lib/util')
const { writeChunksFromStream } = require('./chunkWriter')

const { DEFAULT_CHUNK_SIZE: SHARED_CHUNK_SIZE } = require('../lib/limits')

// Fallback only: the configured chunk size (config.storage.chunkSize) is
// already clamped to the backend limit; this is used when the object service is
// constructed directly (tests, library use).
const DEFAULT_CHUNK_SIZE = SHARED_CHUNK_SIZE
const MAX_TAGS = 10
const DEFAULT_MULTIPART_TTL_DAYS = 7
const INTERNAL = Symbol('ddrive.objects.internal')

const isFile = (node) => node && node.type === 'file'
const isLockedNow = (node) => {
    if (!node) return false
    if (node.legalHold) return true
    if (!node.lockUntil) return false

    return new Date(node.lockUntil).getTime() > Date.now()
}

/** Recursively collect paths that must exist for `key` (a/b/c.txt -> a, a/b). */
const prefixPaths = (key) => {
    const parts = util.normalizeKey(key).split('/').filter(Boolean)
    const out = []
    for (let i = 1; i < parts.length; i += 1) out.push(parts.slice(0, i).join('/'))

    return out
}

class Objects {
    constructor(deps) {
        this.repo = deps.repo
        this.store = deps.store
        this.crypto = deps.crypto
        this.events = deps.events
        this.buckets = deps.buckets
        this.tagger = deps.tagger
        this.audit = deps.audit
        this.logger = deps.logger || console
        this.metrics = deps.metrics
        this.config = {
            chunkSize: DEFAULT_CHUNK_SIZE,
            multipartTtlDays: DEFAULT_MULTIPART_TTL_DAYS,
            ...(deps.config || {}),
        }
        this.INCLUDE_INTERNAL = INTERNAL
    }

    // ------------------------------------------------------------------
    // Lookups
    // ------------------------------------------------------------------

    async getNode(bucketId, path) {
        const clean = path === '' || path === '/' ? '' : util.normalizeKey(path)
        const [node] = await this.repo.find('directory', { bucketId, path: clean }, { limit: 1 })

        return node || null
    }

    async getNodeById(id) {
        return this.repo.findOne('directory', { id })
    }

    /** Resolve a node, tolerating both "key" and "key/" style inputs. */
    async resolve(bucketId, path) {
        const clean = util.normalizeKey(path)
        const direct = await this.getNode(bucketId, clean)
        if (direct && !direct.deletedAt) return direct
        // S3 treats "dir/" as a prefix: expose it as the directory node
        const asDir = await this.getNode(bucketId, clean)
        if (asDir) return asDir

        return null
    }

    /** Create any missing prefix directories for `key` (transaction aware). */
    async ensurePrefixes(repo, bucket, key, opts = {}) {
        const paths = prefixPaths(key)
        let parentId = bucket.id
        for (const p of paths) {
            const name = util.basename(p)
            // eslint-disable-next-line no-await-in-loop
            let node = await repo.findOne('directory', { bucketId: bucket.id, path: p })
            if (!node) {
                // eslint-disable-next-line no-await-in-loop
                node = await repo.insert('directory', {
                    bucketId: bucket.id,
                    parentId,
                    name,
                    path: p,
                    depth: p.split('/').length,
                    type: 'directory',
                    ownerId: opts.ownerId || null,
                    createdBy: opts.createdBy || null,
                })
            }
            parentId = node.id
        }

        return parentId
    }

    /** Ensure the intermediate directories for a key exist, creating them if needed. */
    async ensurePath(bucket, key, opts = {}) {
        return this.repo.transaction(async (tx) => {
            const parentId = await this.ensurePrefixes(tx, bucket, key, opts)
            const name = util.basename(key)
            const existing = await tx.findOne('directory', { bucketId: bucket.id, parentId, name })

            return { parentId, name, existing, tx }
        })
    }

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    /**
     * S3-style listing with prefix/delimiter, or a flat recursive listing.
     * @param {object} opts
     * @param {object} opts.bucket
     * @param {string} [opts.prefix]
     * @param {string} [opts.delimiter]
     * @param {string} [opts.startAfter]
     * @param {number} [opts.maxKeys]
     * @param {boolean} [opts.includeVersions]
     */
    async list(opts) {
        const {
            bucket, prefix = '', delimiter = '', startAfter = '', maxKeys = 1000, includeDirectories = false, includeDeleted = false, marker,
        } = opts
        // S3 semantics: a prefix ending in "/" only matches keys below it; a
        // prefix without it also matches the key itself.
        const rawPrefix = prefix && prefix !== '/' ? prefix : ''
        const cleanPrefix = rawPrefix ? (rawPrefix.endsWith('/') ? rawPrefix : util.normalizeKey(rawPrefix)) : ''
        const where = { bucketId: bucket.id }
        if (!includeDeleted) where.deletedAt = null
        if (cleanPrefix) where.path = { startsWith: cleanPrefix }
        if (!includeDirectories) where.type = 'file'
        const fetchLimit = Math.min(Math.max(maxKeys * 4, 1000), 100000)
        const rows = await this.repo.find('directory', where, {
            orderBy: [{ column: 'path', dir: 'asc' }],
            limit: fetchLimit,
        })
        const cursor = startAfter || marker || ''
        const contents = []
        const commonPrefixes = new Set()
        let truncated = false

        for (const row of rows) {
            if (!row.path) continue // bucket root
            const key = row.path
            if (cursor && key <= cursor) continue
            if (delimiter) {
                const remainder = key.slice(cleanPrefix.length)
                const idx = remainder.indexOf(delimiter)
                if (idx >= 0) {
                    const common = cleanPrefix + remainder.slice(0, idx + delimiter.length)
                    if (!commonPrefixes.has(common) && contents.length + commonPrefixes.size >= maxKeys) {
                        truncated = true
                        break
                    }
                    commonPrefixes.add(common)
                    continue
                }
            }
            contents.push(row)
            if (contents.length + commonPrefixes.size >= maxKeys) {
                truncated = true
                break
            }
        }

        return {
            contents,
            commonPrefixes: [...commonPrefixes].sort(),
            isTruncated: truncated || rows.length >= fetchLimit,
            nextMarker: truncated && contents.length ? contents[contents.length - 1].path : null,
        }
    }

    /** Direct children of a directory (used by WebDAV depth:1 and the console). */
    async children(bucket, dirPath, opts = {}) {
        const clean = util.normalizeKey(dirPath)
        const where = { bucketId: bucket.id, parentId: opts.parentId || (clean ? undefined : bucket.id) }
        if (clean && !opts.parentId) {
            const dir = await this.getNode(bucket.id, clean)
            if (!dir) return []

            return this.children(bucket, clean, { ...opts, parentId: dir.id })
        }
        if (!clean) {
            where.parentId = bucket.id
        }
        const rows = await this.repo.find('directory', where, { orderBy: [{ column: 'name', dir: 'asc' }] })
        const visible = rows.filter((r) => (opts.includeDeleted ? true : !r.deletedAt))
        if (opts.withSize) {
            await Promise.all(visible.filter((r) => r.type === 'directory').map(async (r) => {
                const size = await this.repo.aggregate('directory', 'sum', 'size', {
                    bucketId: bucket.id, type: 'file', deletedAt: null, path: { startsWith: `${r.path}/` },
                })
                r.size = Number(size || 0) // eslint-disable-line no-param-reassign
            }))
        }

        return visible
    }

    // ------------------------------------------------------------------
    // Write path
    // ------------------------------------------------------------------

    /**
     * Chunk + encrypt + persist a stream.
     * @returns {Promise<{ blocks: object[], size: number, etag: string, chunkHashes: string[], encrypted: boolean }>}
     */
    async writeChunks(stream, opts = {}) {
        const chunkSize = Math.min(opts.chunkSize || this.config.chunkSize, this.store.maxChunkSize || DEFAULT_CHUNK_SIZE)
        let encrypted = false
        let wrappedDek = null
        let keyId = null
        let encAlg = null
        let dek = null

        if (this.crypto && this.crypto.enabled) {
            dek = this.crypto.generateDek()
            const wrapped = await this.crypto.wrapDek(dek)
            wrappedDek = wrapped.wrappedDek
            keyId = wrapped.keyId
            encAlg = this.crypto.algorithm
            encrypted = true
        }

        const written = []
        const processChunk = async (data, index) => {
            const plainHash = util.md5(data)
            const payload = encrypted ? this.crypto.encryptChunk(dek, data, encAlg) : null
            const stored = await this.store.put(payload ? payload.data : data, { key: opts.key, tier: opts.tier })
            const block = {
                ordinal: index,
                url: stored.locator,
                size: data.length,
                storedSize: stored.size,
                iv: payload ? payload.iv : null,
                wrappedDek,
                keyId,
                encAlg: payload ? payload.algorithm : null,
                checksum: `md5:${plainHash}`,
                backend: stored.backend,
                tier: stored.tier || 'HOT',
                plainHash,
            }
            written[index] = block

            return block
        }

        try {
            const res = await writeChunksFromStream(stream, {
                chunkSize,
                concurrency: this.store.concurrency || 3,
                onChunk: processChunk,
            })
            const blocks = res.chunks.filter(Boolean)
            const chunkHashes = blocks.map((b) => b.plainHash)
            // S3 semantics: the etag of an empty object is the md5 of nothing
            const etag = blocks.length ? util.combinedEtag(chunkHashes) : util.md5(Buffer.alloc(0))

            return {
                blocks, size: res.size, etag, chunkHashes, encrypted, wrappedDek, keyId, encAlg,
            }
        } catch (err) {
            // best effort cleanup of already uploaded chunks
            await Promise.allSettled(written.filter(Boolean).map((b) => this.store.delete(b.url)))
            throw err
        }
    }

    /** Quota check across bucket and owner. */
    async assertQuota(bucket, ownerId, incomingBytes) {
        if (bucket.quotaBytes) {
            const used = await this.repo.aggregate('directory', 'sum', 'size', { bucketId: bucket.id, type: 'file', deletedAt: null })
            if (Number(used || 0) + incomingBytes > Number(bucket.quotaBytes)) {
                throw errors.quotaExceeded(`Bucket ${bucket.name} has exceeded its quota`)
            }
        }
        if (ownerId) {
            const user = await this.repo.findOne('user', { id: ownerId })
            if (user && user.quotaBytes) {
                const used = await this.repo.aggregate('directory', 'sum', 'size', { bucketId: bucket.id, type: 'file', ownerId, deletedAt: null })
                if (Number(used || 0) + incomingBytes > Number(user.quotaBytes)) {
                    throw errors.quotaExceeded(`User ${user.username} has exceeded the configured quota`)
                }
            }
        }
    }

    /**
     * Put (create or replace) an object.
     *
     * @param {object} opts
     * @param {object} opts.bucket
     * @param {string} opts.path
     * @param {Readable} opts.stream
     * @param {string} [opts.contentType]
     * @param {object} [opts.metadata]
     * @param {object} [opts.tags]
     * @param {string} [opts.storageClass]
     * @param {string} [opts.tier]
     * @param {object} [opts.actor]     { id, name, type, protocol, ip, requestId }
     * @param {object} [opts.conditions] { ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince }
     * @param {string} [opts.retentionMode] GOVERNANCE | COMPLIANCE
     * @param {string|Date} [opts.retainUntil]
     * @param {boolean} [opts.legalHold]
     */
    async putObject(opts) {
        const {
            bucket, path, stream, contentType, metadata, tags, storageClass, tier,
            actor = {}, conditions = {}, retentionMode, retainUntil, legalHold, contentMd5,
        } = opts
        const key = util.normalizeKey(path)
        if (!key) throw errors.invalidArgument('Object key is empty')
        if (key.length > 1024) throw new StorageError('KeyTooLong', 'The object key is longer than 1024 bytes.', { statusCode: 400 })

        const existing = await this.getNode(bucket.id, key)
        const versioning = bucket.versioning === 'enabled' ? 'enabled' : bucket.versioning === 'suspended' ? 'suspended' : 'off'

        // Conditions (S3 If-Match / If-None-Match / If-(Un)Modified-Since)
        this.assertConditions(existing, conditions)

        // Object lock: overwriting a locked object requires bypass
        if (existing && isFile(existing) && isLockedNow(existing) && !conditions.bypassGovernance) {
            throw errors.objectLocked(`Object ${key} is protected until ${util.iso(existing.lockUntil) || 'forever'} (${existing.lockMode || 'LEGAL_HOLD'})`)
        }

        const written = await this.writeChunks(stream, { key, tier: tier || this.tierForStorageClass(storageClass || bucket.defaultStorageClass) })
        await this.assertQuota(bucket, actor.id || null, written.size)

        if (contentMd5 && written.chunkHashes.length === 1) {
            const expected = String(contentMd5).replace(/^.*:/, '')
            if (!util.timingSafeEqual(expected.toLowerCase(), written.chunkHashes[0].toLowerCase())) {
                await Promise.allSettled(written.blocks.map((b) => this.store.delete(b.url)))
                throw errors.validation('The Content-MD5 you specified did not match what we received.', { expected })
            }
        }

        const versionId = randomUUID()
        const now = new Date()
        const retention = this.resolveRetention(bucket, { retentionMode, retainUntil, legalHold })

        const result = await this.repo.transaction(async (tx) => {
            const parentId = await this.ensurePrefixes(tx, bucket, key, actor)
            const name = util.basename(key)
            let node = await tx.findOne('directory', { bucketId: bucket.id, parentId, name })
            let versionNumber = 1
            let replacedVersion = null

            if (node) {
                const latest = node.latestVersionId
                    ? await tx.findOne('object_version', { id: node.latestVersionId })
                    : null
                if (latest) versionNumber = Number(latest.versionNumber) + 1
                if (versioning !== 'enabled') {
                    replacedVersion = latest
                }
            } else {
                node = await tx.insert('directory', {
                    id: randomUUID(),
                    bucketId: bucket.id,
                    parentId,
                    name,
                    path: key,
                    depth: key.split('/').length,
                    type: 'file',
                    ownerId: actor.id || null,
                    createdBy: actor.name || null,
                })
            }

            // a new write always clears the S3 delete marker state
            const objectId = node.id
            if (versioning === 'enabled' && node.latestVersionId) {
                await tx.update('object_version', { objectId, isLatest: true }, { isLatest: false })
            }

            await tx.insert('object_version', {
                id: versionId,
                objectId,
                bucketId: bucket.id,
                path: key,
                versionNumber,
                isLatest: true,
                isDeleteMarker: false,
                size: written.size,
                etag: written.etag,
                checksum: written.chunkHashes.length ? `md5:${written.etag}` : null,
                contentType: contentType || null,
                metadata: metadata || null,
                tags: this.normalizeTags(tags),
                storageClass: storageClass || bucket.defaultStorageClass || 'STANDARD',
                tier: this.tierForStorageClass(storageClass || bucket.defaultStorageClass),
                encAlg: written.encAlg,
                keyId: written.keyId,
                wrappedDek: written.wrappedDek,
                createdBy: actor.name || null,
                ownerId: actor.id || null,
                retentionMode: retention.mode,
                retainUntil: retention.until,
                legalHold: retention.legalHold,
            })

            const blockRows = written.blocks.map((b) => ({
                fileId: objectId,
                versionId,
                ordinal: b.ordinal,
                partNumber: null,
                uploadId: null,
                url: b.url,
                size: b.size,
                iv: b.iv,
                wrappedDek: b.wrappedDek,
                keyId: b.keyId,
                encAlg: b.encAlg,
                checksum: b.checksum,
                backend: b.backend,
                tier: b.tier,
            }))
            if (blockRows.length) await tx.insertMany('block', blockRows)

            await tx.update('directory', { id: objectId }, {
                size: written.size,
                etag: written.etag,
                checksum: `md5:${written.etag}`,
                contentType: contentType || node.contentType || null,
                storageClass: storageClass || bucket.defaultStorageClass || 'STANDARD',
                metadata: metadata || node.metadata || null,
                tags: this.normalizeTags(tags) || node.tags || null,
                latestVersionId: versionId,
                deletedAt: null,
                lockMode: retention.mode || null,
                lockUntil: retention.until || null,
                legalHold: retention.legalHold,
                ownerId: actor.id || node.ownerId || null,
                updatedAt: now,
            })

            if (replacedVersion) {
                await tx.delete('object_version', { id: replacedVersion.id })
            }

            return { objectId, versionId, versionNumber, replacedVersion }
        })

        // Versions replaced by an unversioned PUT are purged outside the tx
        if (result.replacedVersion) {
            await this.purgeVersion(result.replacedVersion)
        }

        const node = await this.getNodeById(result.objectId)
        await this.onVersionWritten({ bucket, node, versionId, size: written.size, actor, encryption: written.encrypted })
        await this.recordAudit('object.put', {
            bucket,
            node,
            actor,
            detail: {
                versionId: result.versionId,
                versionNumber: result.versionNumber,
                size: written.size,
                etag: written.etag,
                storageClass: storageClass || bucket.defaultStorageClass || 'STANDARD',
                encryption: this.encryptionDetail(written),
                replacedVersionId: result.replacedVersion ? result.replacedVersion.id : null,
            },
        })
        if (this.tagger) await this.tagger.applyOnUpload({ bucket, node, actor }).catch((err) => this.logger.warn?.({ err }, 'auto-tag failed'))

        return { node, versionId: result.versionId, etag: written.etag, size: written.size }
    }

    /** Update object metadata/tags/retention without rewriting content (S3 CopyObject with REPLACE). */
    async updateObject(bucket, path, patch, actor = {}) {
        const key = util.normalizeKey(path)
        const node = await this.getNode(bucket.id, key)
        if (!isFile(node)) throw errors.noSuchKey(key)
        const allowed = {}
        if (patch.contentType !== undefined) allowed.contentType = patch.contentType
        if (patch.metadata !== undefined) allowed.metadata = patch.metadata
        if (patch.storageClass !== undefined) allowed.storageClass = patch.storageClass
        if (patch.tags !== undefined) allowed.tags = this.normalizeTags(patch.tags)
        if (patch.retentionMode !== undefined || patch.retainUntil !== undefined || patch.legalHold !== undefined) {
            const retention = this.resolveRetention(bucket, {
                retentionMode: patch.retentionMode ?? node.lockMode,
                retainUntil: patch.retainUntil ?? node.lockUntil,
                legalHold: patch.legalHold ?? node.legalHold,
            })
            allowed.lockMode = retention.mode
            allowed.lockUntil = retention.until
            allowed.legalHold = retention.legalHold
        }
        if (!Object.keys(allowed).length) return node
        await this.repo.transaction(async (tx) => {
            await tx.update('directory', { id: node.id }, allowed)
            if (node.latestVersionId) {
                const versionPatch = {}
                if (allowed.contentType !== undefined) versionPatch.contentType = allowed.contentType
                if (allowed.metadata !== undefined) versionPatch.metadata = allowed.metadata
                if (allowed.storageClass !== undefined) versionPatch.storageClass = allowed.storageClass
                if (allowed.tags !== undefined) versionPatch.tags = allowed.tags
                if (allowed.lockMode !== undefined) versionPatch.retentionMode = allowed.lockMode
                if (allowed.lockUntil !== undefined) versionPatch.retainUntil = allowed.lockUntil
                if (allowed.legalHold !== undefined) versionPatch.legalHold = allowed.legalHold
                if (Object.keys(versionPatch).length) {
                    await tx.update('object_version', { id: node.latestVersionId }, versionPatch)
                }
            }
        })
        const updated = await this.getNodeById(node.id)
        this.emit('OBJECT_METADATA_UPDATED', { bucket, node: updated, actor })

        return updated
    }

    resolveRetention(bucket, opts = {}) {
        const mode = opts.retentionMode || (bucket.defaultRetentionDays ? bucket.defaultRetentionMode : null)
        let until = opts.retainUntil || null
        if (!until && bucket.defaultRetentionDays && mode) {
            until = util.addDays(new Date(), Number(bucket.defaultRetentionDays))
        }
        if (until && typeof until === 'string') until = new Date(until)
        if (mode && !until) throw errors.invalidArgument('Retention mode requires RetainUntilDate')
        if (!bucket.objectLockEnabled && (mode || opts.legalHold)) {
            throw errors.invalidRequest('Object Lock is not enabled for this bucket')
        }

        return { mode: mode || null, until, legalHold: !!opts.legalHold || (!mode && !opts.legalHold ? false : !!(opts.legalHold)) }
    }

    assertConditions(node, conditions = {}) {
        if (!conditions || !Object.keys(conditions).length) return
        const etag = node && node.etag ? node.etag : null
        const matches = (candidate) => {
            const value = String(candidate).replace(/"/g, '')
            if (value === '*') return !!etag
            if (value.startsWith('W/')) return false

            return value.split(',').some((v) => v.trim() === etag)
        }
        if (conditions.ifMatch !== undefined && !matches(conditions.ifMatch)) {
            throw errors.preconditionFailed('If-Match condition failed', { ifMatch: conditions.ifMatch })
        }
        if (conditions.ifNoneMatch !== undefined && matches(conditions.ifNoneMatch)) {
            throw errors.preconditionFailed('If-None-Match condition failed', { ifNoneMatch: conditions.ifNoneMatch })
        }
        const modified = node && node.updatedAt ? new Date(node.updatedAt) : null
        if (conditions.ifModifiedSince && (!modified || modified <= new Date(conditions.ifModifiedSince))) {
            throw errors.preconditionFailed('If-Modified-Since condition failed')
        }
        if (conditions.ifUnmodifiedSince && modified && modified > new Date(conditions.ifUnmodifiedSince)) {
            throw errors.preconditionFailed('If-Unmodified-Since condition failed')
        }
    }

    // ------------------------------------------------------------------
    // Read path
    // ------------------------------------------------------------------

    async getVersion(bucket, path, versionId) {
        const node = await this.getNode(bucket.id, path)
        if (!node) throw errors.noSuchKey(path)
        if (versionId) {
            const version = await this.repo.findOne('object_version', { id: versionId, objectId: node.id })
            if (!version) throw errors.noSuchVersion(versionId)

            return { node, version }
        }
        if (!node.latestVersionId) throw errors.noSuchKey(path)
        const version = await this.repo.findOne('object_version', { id: node.latestVersionId })
        if (!version) throw errors.noSuchKey(path)
        if (version.isDeleteMarker) {
            const err = errors.noSuchKey(path)
            err.detail = { deleteMarker: true, versionId: version.id }

            throw err
        }

        return { node, version }
    }

    async blocksOf(versionId) {
        return this.repo.find('block', { versionId }, { orderBy: [{ column: 'ordinal', dir: 'asc' }] })
    }

    /**
     * Stream a version's bytes.
     * @param {object} version
     * @param {object} [range] { start, end } inclusive byte offsets
     * @returns {Promise<{ stream: Readable, length: number, range: object|null, size: number }>}
     */
    async stream(version, range = null) {
        const blocks = await this.blocksOf(version.id)
        if (!blocks.length) {
            if (version.size) throw errors.internal('Corrupt object: no chunks found')
            const stream = Readable.from([])

            return {
                stream, length: 0, range: null, size: 0,
            }
        }
        const size = blocks.reduce((acc, b) => acc + Number(b.size), 0)
        let start = 0
        let end = size - 1
        if (range) {
            start = range.start
            end = range.end
        }
        if (start < 0 || end >= size || start > end) throw errors.invalidRange(size)

        // Map the byte range onto the chunk list
        let offset = 0
        const selected = []
        for (const block of blocks) {
            const blockStart = offset
            const blockEnd = offset + Number(block.size) - 1
            offset += Number(block.size)
            if (blockEnd < start || blockStart > end) continue
            selected.push({
                block,
                start: Math.max(0, start - blockStart),
                end: Math.min(Number(block.size) - 1, end - blockStart),
            })
        }

        const length = end - start + 1
        const out = new PassThrough()
        const self = this
        const pump = async () => {
            try {
                for (const item of selected) {
                    const { block } = item
                    const encrypted = !!block.iv
                    // AEAD (GCM) cannot be decrypted from a partial ciphertext,
                    // so encrypted chunks are fetched whole and sliced in memory
                    // (bounded by the chunk size, default 24 MiB).
                    let source
                    try {
                        source = await self.store.get(block.url, encrypted ? {} : { start: item.start, end: item.end })
                    } catch (err) {
                        out.destroy(err)

                        return
                    }
                    if (!encrypted) {
                        await new Promise((resolve, reject) => {
                            source.on('error', reject)
                            out.on('error', reject)
                            source.on('end', resolve)
                            source.pipe(out, { end: false })
                        })
                        continue
                    }
                    const decipher = block.wrappedDek
                        ? await self.crypto.unwrapAndDecipher({ iv: block.iv, wrappedDek: block.wrappedDek, encAlg: block.encAlg })
                        : self.crypto.legacyDecipher(block.iv)
                    const plain = await new Promise((resolve, reject) => {
                        const chunks = []
                        source.on('error', reject)
                        decipher.on('error', reject)
                        decipher.on('data', (chunk) => chunks.push(chunk))
                        decipher.on('end', () => resolve(Buffer.concat(chunks)))
                        source.pipe(decipher)
                    })
                    const slice = item.start === 0 && item.end === plain.length - 1
                        ? plain
                        : plain.subarray(item.start, item.end + 1)
                    if (slice.length && !out.write(slice)) {
                        await new Promise((resolve) => out.once('drain', resolve))
                    }
                }
                out.end()
            } catch (err) {
                out.destroy(err)
            }
        }
        pump()

        return {
            stream: out, length, range: range ? { start, end } : null, size,
        }
    }

    /** Record access statistics (feeds intelligent tiering). */
    async recordAccess(version, bytes = 0) {
        if (!version || !version.objectId) return
        await this.repo.update('object_version', { id: version.id }, { tieredAt: null }).catch(() => {})
        await this.repo.run(
            'update "directory" set "accessCount" = coalesce("accessCount", 0) + 1, "lastAccessAt" = ?, "bytesServed" = coalesce("bytesServed", 0) + ? where "id" = ?',
            [new Date(), Number(bytes) || 0, version.objectId],
        ).catch(() => {})
    }

    // ------------------------------------------------------------------
    // Delete / move / copy
    // ------------------------------------------------------------------

    /**
     * Delete an object (or a specific version).
     * @param {object} opts { bucket, path, versionId, bypassGovernance, actor, permanent }
     */
    async deleteObject(opts) {
        const {
            bucket, path, versionId, bypassGovernance = false, actor = {}, permanent = false,
            recursive,
        } = opts
        const key = util.normalizeKey(path)
        const node = await this.getNode(bucket.id, key)
        if (!node) {
            // S3 semantics: deleting a missing key is a success
            return { deleted: false, deleteMarker: false }
        }

        // A prefix / explicit folder is not an object. Deleting the folder row
        // on its own would orphan every child (and, once the prefix is recreated,
        // silently fork duplicated keys), so route it through deleteDirectory.
        if (node.type === 'directory') {
            const recurse = recursive !== undefined ? !!recursive : (opts.children ? true : false)
            if (recurse) {
                await this.deleteDirectory(bucket, key, {
                    recursive: true, permanent: permanent !== false, actor,
                })

                return { deleted: true, deleteMarker: false, directory: true }
            }
            const children = await this.children(bucket, key, { includeDeleted: true, parentId: node.id })
            if (children.length) return { deleted: false, deleteMarker: false, directory: true }
            await this.deleteDirectory(bucket, key, { recursive: false, actor })

            return { deleted: true, deleteMarker: false, directory: true }
        }

        const versioning = bucket.versioning === 'enabled'

        if (versionId) {
            const version = await this.repo.findOne('object_version', { id: versionId, objectId: node.id })
            if (!version) throw errors.noSuchVersion(versionId)
            this.assertUnlocked(version, `${key}@${versionId}`, bypassGovernance)
            await this.repo.transaction(async (tx) => {
                await tx.delete('object_version', { id: version.id })
                if (node.latestVersionId === version.id) {
                    const previous = await tx.findOne('object_version', { objectId: node.id }, { orderBy: [{ column: 'versionNumber', dir: 'desc' }] })
                    if (previous) {
                        await tx.update('object_version', { id: previous.id }, { isLatest: true })
                        await tx.update('directory', { id: node.id }, { latestVersionId: previous.id, deletedAt: previous.isDeleteMarker ? new Date() : null })
                    } else {
                        await tx.delete('directory', { id: node.id })
                    }
                }
            })
            await this.purgeVersion(version)
            this.emit('VERSION_REMOVED', { bucket, node, version, actor })
            await this.recordAudit('object.version.delete', {
                bucket, node, version, actor, detail: { permanent: true, size: Number(version.size || 0) },
            })

            return { deleted: true, deleteMarker: false, versionId }
        }

        // no versionId: latest version
        const latest = node.latestVersionId ? await this.repo.findOne('object_version', { id: node.latestVersionId }) : null
        if (latest && !permanent) this.assertUnlocked(latest, key, bypassGovernance)

        if (versioning && !permanent) {
            // create a delete marker
            const transaction = await this.repo.transaction(async (tx) => {
                const nextNumber = latest ? Number(latest.versionNumber) + 1 : 1
                await tx.update('object_version', { objectId: node.id, isLatest: true }, { isLatest: false })
                const marker = await tx.insert('object_version', {
                    objectId: node.id,
                    bucketId: bucket.id,
                    path: key,
                    versionNumber: nextNumber,
                    isLatest: true,
                    isDeleteMarker: true,
                    size: 0,
                    createdBy: actor.name || null,
                    ownerId: actor.id || null,
                })
                await tx.update('directory', { id: node.id }, {
                    latestVersionId: marker.id, deletedAt: new Date(), updatedAt: new Date(),
                })

                return marker
            })
            this.emit('OBJECT_DELETE_MARKER_CREATED', { bucket, node, version: transaction, actor })
            await this.recordAudit('object.delete_marker', {
                bucket, node, actor, detail: { versionId: transaction.id, versionNumber: Number(transaction.versionNumber) },
            })

            return { deleted: true, deleteMarker: true, versionId: transaction.id }
        }

        // unversioned delete: remove the object row, all versions and chunks
        const versions = await this.repo.find('object_version', { objectId: node.id })
        await this.repo.transaction(async (tx) => {
            await tx.delete('object_version', { objectId: node.id })
            await tx.delete('directory', { id: node.id })
        })
        await Promise.all(versions.map((v) => this.purgeVersion(v)))
        await this.repo.delete('object_tag', { objectId: node.id })
        if (this.tagger) await this.tagger.removeObjectTags(node.id).catch(() => {})
        this.emit('OBJECT_REMOVED', { bucket, node, actor })
        await this.recordAudit('object.delete', {
            bucket, node, actor, detail: { versionsRemoved: versions.length, permanent: true },
        })

        return { deleted: true, deleteMarker: false }
    }

    /**
     * Permanently delete a version: chunk blobs are only removed when no other
     * block (e.g. a server side copy) still references the same locator.
     */
    async purgeVersion(version) {
        if (!version) return
        const blocks = await this.repo.find('block', { versionId: version.id })
        await this.releaseChunks(blocks)
        await this.repo.delete('block', { versionId: version.id })
    }

    /** Delete chunk blobs that are not referenced by any other block row. */
    async releaseChunks(blocks) {
        const urls = [...new Set(blocks.map((b) => b.url).filter(Boolean))]
        if (!urls.length) return
        const counts = new Map()
        for (const urlBatch of util.chunkArray(urls, 200)) {
            // eslint-disable-next-line no-await-in-loop
            const rows = await this.repo.all(
                `select "url", count(*) as count from "block" where "url" in (${urlBatch.map(() => '?').join(', ')}) group by "url"`,
                urlBatch,
            )
            rows.forEach((r) => counts.set(r.url, Number(r.count)))
        }
        await Promise.allSettled(blocks
            .filter((b) => (counts.get(b.url) || 0) <= 1)
            .map((b) => this.store.delete(b.url)))
    }

    assertUnlocked(version, label, bypassGovernance) {
        if (!version) return
        const held = version.legalHold
        const until = version.retainUntil ? new Date(version.retainUntil) : null
        const locked = until && until.getTime() > Date.now()
        if (!held && !locked) return
        if (bypassGovernance && !held && version.retentionMode === 'GOVERNANCE') return
        throw errors.objectLocked(
            `Object ${label} is protected${held ? ' by a legal hold' : ` until ${util.iso(until)} (${version.retentionMode})`}`,
            { legalHold: !!held, retainUntil: util.iso(until), mode: version.retentionMode },
        )
    }

    /** Delete an empty directory (WebDAV DELETE on a collection). */
    async deleteDirectory(bucket, path, opts = {}) {
        const key = util.normalizeKey(path)
        const node = await this.getNode(bucket.id, key)
        if (!node) throw errors.noSuchKey(key)
        const recursive = opts.recursive !== undefined ? !!opts.recursive : (opts.children ? true : false)
        if (recursive) {
            const descendants = await this.repo.find('directory', {
                bucketId: bucket.id, path: { startsWith: `${key}/` },
            })
            for (const child of descendants.filter((row) => row.type === 'file')) {
                // eslint-disable-next-line no-await-in-loop
                await this.deleteObject({
                    bucket, path: child.path, permanent: opts.permanent !== false, actor: opts.actor,
                })
            }
            const dirs = descendants.filter((row) => row.type === 'directory').sort((a, b) => b.path.length - a.path.length)
            for (const dir of dirs) {
                // eslint-disable-next-line no-await-in-loop
                await this.repo.delete('directory', { id: dir.id })
            }
        } else {
            const children = await this.children(bucket, key, { includeDeleted: true, parentId: node.id })
            if (children.length) throw errors.bucketNotEmpty(key)
        }
        await this.repo.delete('directory', { id: node.id })
        this.emit('DIRECTORY_REMOVED', { bucket, node, actor: opts.actor })
        await this.recordAudit('directory.delete', {
            bucket, node, actor: opts.actor, detail: { recursive: !!opts.recursive },
        })

        return true
    }

    /** Create an explicit (empty) directory - WebDAV MKCOL, console "new folder". */
    async createDirectory(bucket, path, opts = {}) {
        const key = util.normalizeKey(path)
        if (!key) throw errors.invalidArgument('Directory name is empty')
        const node = await this.getNode(bucket.id, key)
        if (node && !node.deletedAt) return node
        return this.repo.transaction(async (tx) => {
            const parentId = await this.ensurePrefixes(tx, bucket, key, opts)
            const created = await tx.insert('directory', {
                bucketId: bucket.id,
                parentId,
                name: util.basename(key),
                path: key,
                depth: key.split('/').length,
                type: 'directory',
                ownerId: opts.actor?.id || null,
                createdBy: opts.actor?.name || null,
            })
            this.emit('DIRECTORY_CREATED', { bucket, node: created, actor: opts.actor })
            await this.recordAudit('directory.create', { bucket, node: created, actor: opts.actor, detail: {} })

            return created
        })
    }

    /** Rename / move a file or an entire subtree. */
    async move(bucket, fromPath, toPath, opts = {}) {
        const from = util.normalizeKey(fromPath)
        const to = util.normalizeKey(toPath)
        if (!from || !to) throw errors.invalidArgument('Source and destination paths are required')
        if (from === to) return this.getNode(bucket.id, to)
        if (util.isSubPath(from, to)) throw errors.invalidArgument('Cannot move a directory into itself')

        const node = await this.getNode(bucket.id, from)
        if (!node) throw errors.noSuchKey(from)
        const target = await this.getNode(bucket.id, to)
        if (target && !opts.overwrite) throw errors.conflict(`Object ${to} already exists`, { path: to })
        if (isFile(node)) {
            if (target && target.type === 'directory') throw errors.conflict('Cannot overwrite a directory with a file')
            if (node.latestVersionId) {
                const version = await this.repo.findOne('object_version', { id: node.latestVersionId })
                if (version) this.assertUnlocked(version, from, opts.bypassGovernance)
            }
        }

        const result = await this.repo.transaction(async (tx) => {
            const parentId = await this.ensurePrefixes(tx, bucket, to, opts.actor)
            const name = util.basename(to)
            const depthDelta = to.split('/').length - from.split('/').length
            if (target) {
                if (isFile(target)) {
                    const versions = await tx.find('object_version', { objectId: target.id })
                    await tx.delete('object_version', { objectId: target.id })
                    await tx.delete('directory', { id: target.id })
                    await Promise.all(versions.map((v) => this.purgeVersion(v)))
                } else {
                    await tx.delete('directory', { id: target.id })
                }
            }
            await tx.update('directory', { id: node.id }, {
                parentId, name, path: to, depth: to.split('/').length,
            })
            if (node.type === 'directory') {
                // rewrite descendants
                await tx.run(
                    `update "directory" set "path" = ? || substr("path", ?), "depth" = "depth" + ? where "bucketId" = ? and "path" like ?`,
                    [to, from.length + 1, depthDelta, bucket.id, `${from}/%`],
                )
                await tx.run(
                    `update "object_version" set "path" = ? || substr("path", ?) where "bucketId" = ? and "path" like ?`,
                    [to, from.length + 1, bucket.id, `${from}/%`],
                )
            }
            await tx.run('update "object_version" set "path" = ? where "objectId" = ?', [to, node.id])

            return tx.findOne('directory', { id: node.id })
        })

        this.emit('OBJECT_MOVED', {
            bucket, node: result, actor: opts.actor, from, to,
        })
        await this.recordAudit('object.move', {
            bucket, node: result, actor: opts.actor, detail: { from, to },
        })

        return result
    }

    /** Copy an object or subtree. */
    async copy(source, target, opts = {}) {
        const versioning = target.bucket.versioning === 'enabled'
        const sourceNode = await this.getNode(source.bucket.id, source.path)
        if (!sourceNode) throw errors.noSuchKey(source.path)

        if (sourceNode.type === 'directory') {
            const rows = await this.repo.find('directory', {
                bucketId: source.bucket.id, path: { startsWith: `${util.normalizeKey(source.path)}/` },
            })
            await this.createDirectory(target.bucket, target.path, opts)
            for (const row of rows) {
                const relative = row.path.slice(util.normalizeKey(source.path).length + 1)
                const destPath = `${util.normalizeKey(target.path)}/${relative}`
                if (row.type === 'file') {
                    // eslint-disable-next-line no-await-in-loop
                    await this.copy({ bucket: source.bucket, path: row.path }, { bucket: target.bucket, path: destPath }, opts)
                } else {
                    // eslint-disable-next-line no-await-in-loop
                    await this.createDirectory(target.bucket, destPath, opts)
                }
            }

            return { copied: rows.length, type: 'directory' }
        }

        const { version } = await this.getVersion(source.bucket, source.path, source.versionId)
        const parentId = await this.repo.transaction((tx) => this.ensurePrefixes(tx, target.bucket, target.path, opts.actor))
        const name = util.basename(target.path)
        const existing = await this.repo.findOne('directory', { bucketId: target.bucket.id, parentId, name })
        if (existing && !opts.overwrite) throw errors.preconditionFailed('Destination object already exists')

        const targetVersionId = randomUUID()
        const targetObjectId = existing ? existing.id : randomUUID()
        const blocks = await this.blocksOf(version.id)

        await this.repo.transaction(async (tx) => {
            if (!existing) {
                await tx.insert('directory', {
                    id: targetObjectId,
                    bucketId: target.bucket.id,
                    parentId,
                    name,
                    path: util.normalizeKey(target.path),
                    depth: util.normalizeKey(target.path).split('/').length,
                    type: 'file',
                    ownerId: opts.actor?.id || null,
                    createdBy: opts.actor?.name || null,
                })
            }
            const versionNumber = existing && existing.latestVersionId
                ? Number((await tx.findOne('object_version', { id: existing.latestVersionId }))?.versionNumber || 0) + 1
                : 1
            if (versioning && existing && existing.latestVersionId) {
                await tx.update('object_version', { objectId: targetObjectId, isLatest: true }, { isLatest: false })
            }
            const metadataDirective = (opts.metadataDirective || 'COPY').toUpperCase()
            const newVersion = await tx.insert('object_version', {
                id: targetVersionId,
                objectId: targetObjectId,
                bucketId: target.bucket.id,
                path: util.normalizeKey(target.path),
                versionNumber,
                isLatest: true,
                size: version.size,
                etag: version.etag,
                checksum: version.checksum,
                contentType: opts.contentType || version.contentType,
                metadata: metadataDirective === 'REPLACE' ? (opts.metadata || null) : version.metadata,
                tags: metadataDirective === 'REPLACE' ? this.normalizeTags(opts.tags) : version.tags,
                storageClass: opts.storageClass || version.storageClass || 'STANDARD',
                tier: opts.tier || version.tier || 'HOT',
                encAlg: version.encAlg,
                keyId: version.keyId,
                wrappedDek: version.wrappedDek,
                createdBy: opts.actor?.name || null,
                ownerId: opts.actor?.id || null,
                replicationStatus: 'none',
            })
            // Share the underlying chunks (copy-on-write): a chunk is immutable
            // and only deleted when no other block references it.
            if (blocks.length) {
                await tx.insertMany('block', blocks.map((b) => ({
                    versionId: targetVersionId,
                    fileId: targetObjectId,
                    ordinal: b.ordinal,
                    url: b.url,
                    size: b.size,
                    iv: b.iv,
                    wrappedDek: b.wrappedDek,
                    keyId: b.keyId,
                    encAlg: b.encAlg,
                    checksum: b.checksum,
                    backend: b.backend,
                    tier: b.tier,
                })))
            }
            await tx.update('directory', { id: targetObjectId }, {
                size: version.size,
                etag: version.etag,
                checksum: version.checksum,
                contentType: opts.contentType || version.contentType,
                metadata: metadataDirective === 'REPLACE' ? (opts.metadata || null) : version.metadata,
                tags: metadataDirective === 'REPLACE' ? this.normalizeTags(opts.tags) : version.tags,
                storageClass: opts.storageClass || version.storageClass || 'STANDARD',
                latestVersionId: newVersion.id,
                deletedAt: null,
            })
        })

        const node = await this.getNodeById(targetObjectId)
        this.emit('OBJECT_COPIED', {
            bucket: target.bucket, node, actor: opts.actor, source,
        })
        await this.recordAudit('object.copy', {
            bucket: target.bucket,
            node,
            actor: opts.actor,
            detail: {
                source: `${source.bucket.name}/${source.path}`,
                versionId: targetVersionId,
                size: Number(version.size || 0),
                encryption: {
                    enabled: !!version.encAlg, algorithm: version.encAlg || null, keyId: version.keyId || null, envelope: !!version.wrappedDek,
                },
            },
        })

        return {
            node, versionId: targetVersionId, etag: version.etag, size: version.size,
        }
    }

    // ------------------------------------------------------------------
    // Versions
    // ------------------------------------------------------------------

    async listVersions(bucket, opts = {}) {
        const {
            prefix = '', maxKeys = 1000, keyMarker, versionIdMarker,
        } = opts
        const cleanPrefix = prefix ? util.normalizeKey(prefix) : ''
        const where = { bucketId: bucket.id }
        if (cleanPrefix) where.path = { startsWith: cleanPrefix }
        const rows = await this.repo.find('object_version', where, {
            orderBy: [{ column: 'path', dir: 'asc' }, { column: 'versionNumber', dir: 'desc' }],
            limit: Math.min(maxKeys, 1000) + 1,
        })
        let filtered = rows
        if (keyMarker) {
            filtered = rows.filter((v) => (v.path > keyMarker) || (v.path === keyMarker && String(v.id) > String(versionIdMarker || '')))
        }
        const isTruncated = filtered.length > maxKeys
        const page = filtered.slice(0, maxKeys)

        return {
            versions: page, isTruncated, keyMarker: page.length ? page[page.length - 1].path : null,
        }
    }

    // ------------------------------------------------------------------
    // Multipart upload
    // ------------------------------------------------------------------

    async initiateMultipart(opts) {
        const {
            bucket, path, contentType, metadata, tags, storageClass, actor = {},
        } = opts
        const key = util.normalizeKey(path)
        const upload = await this.repo.insert('multipart_upload', {
            bucketId: bucket.id,
            name: key,
            contentType: contentType || null,
            metadata: metadata || null,
            tags: this.normalizeTags(tags),
            storageClass: storageClass || bucket.defaultStorageClass || 'STANDARD',
            ownerId: actor.id || null,
            createdBy: actor.name || null,
            status: 'in-progress',
            expiresAt: util.addDays(new Date(), this.config.multipartTtlDays),
        })
        await this.recordAudit('multipart.initiate', {
            bucket, actor, objectKey: key, detail: { uploadId: upload.id, key, storageClass: upload.storageClass },
        })

        return { uploadId: upload.id, ...upload }
    }

    async getUpload(bucket, uploadId) {
        const upload = await this.repo.findOne('multipart_upload', { id: uploadId, bucketId: bucket.id })
        if (!upload || upload.status !== 'in-progress') throw errors.noSuchUpload(uploadId)

        return upload
    }

    async uploadPart(bucket, uploadId, partNumber, stream) {
        await this.getUpload(bucket, uploadId)
        const written = await this.writeChunks(stream, { key: uploadId })
        const etag = written.chunkHashes.length ? util.combinedEtag(written.chunkHashes) : util.md5(Buffer.alloc(0))
        await this.repo.transaction(async (tx) => {
            await tx.delete('block', { uploadId, partNumber })
            await tx.delete('multipart_part', { uploadId, partNumber })
            await tx.insert('multipart_part', {
                uploadId, partNumber, size: written.size, etag: `"${etag}"`, checksum: `md5:${etag}`,
            })
            await tx.insertMany('block', written.blocks.map((b) => ({
                uploadId,
                partNumber,
                ordinal: b.ordinal,
                url: b.url,
                size: b.size,
                iv: b.iv,
                wrappedDek: b.wrappedDek,
                keyId: b.keyId,
                encAlg: b.encAlg,
                checksum: b.checksum,
                backend: b.backend,
                tier: b.tier,
            })))
        })

        return { etag: `"${etag}"`, size: written.size }
    }

    async listParts(bucket, uploadId) {
        await this.getUpload(bucket, uploadId)
        const parts = await this.repo.find('multipart_part', { uploadId }, { orderBy: [{ column: 'partNumber', dir: 'asc' }] })

        return parts
    }

    async abortMultipart(bucket, uploadId, actor = {}) {
        const upload = await this.getUpload(bucket, uploadId)
        const blocks = await this.repo.find('block', { uploadId })
        await Promise.allSettled(blocks.map((b) => this.store.delete(b.url)))
        await this.repo.transaction(async (tx) => {
            await tx.delete('block', { uploadId })
            await tx.delete('multipart_part', { uploadId })
            await tx.update('multipart_upload', { id: uploadId }, { status: 'aborted' })
        })
        await this.recordAudit('multipart.abort', {
            bucket, actor, objectKey: upload?.name || null, detail: { uploadId, partsDiscarded: blocks.length },
        })

        return true
    }

    async listMultipartUploads(bucket) {
        return this.repo.find('multipart_upload', { bucketId: bucket.id, status: 'in-progress' }, { orderBy: [{ column: 'createdAt', dir: 'desc' }] })
    }

    /**
     * Complete a multipart upload: parts are concatenated logically; the object
     * keeps one chunk per part (S3 semantics) and the etag is md5-of-md5s-N.
     */
    async completeMultipart(bucket, uploadId, parts, actor = {}) {
        const upload = await this.getUpload(bucket, uploadId)
        const storedParts = await this.listParts(bucket, uploadId)
        if (!storedParts.length) throw errors.invalidRequest('No parts were uploaded')
        const requested = parts && parts.length ? parts : storedParts.map((p) => ({ partNumber: p.partNumber, etag: p.etag }))
        const ordered = [...requested].sort((a, b) => Number(a.partNumber) - Number(b.partNumber))
        ordered.forEach((p, idx) => {
            if (idx > 0 && Number(p.partNumber) <= Number(ordered[idx - 1].partNumber)) throw errors.invalidPartOrder()
            const stored = storedParts.find((s) => Number(s.partNumber) === Number(p.partNumber))
            if (!stored) throw errors.invalidPart(p.partNumber)
            if (p.etag && String(p.etag).replace(/"/g, '') !== String(stored.etag).replace(/"/g, '')) throw errors.invalidPart(p.partNumber)
        })

        const key = util.normalizeKey(upload.name)
        const versionId = randomUUID()
        const now = new Date()
        const totalSize = ordered.reduce((acc, p) => acc + Number(storedParts.find((s) => Number(s.partNumber) === Number(p.partNumber)).size), 0)
        await this.assertQuota(bucket, upload.ownerId, totalSize)
        const etag = util.multipartEtag(ordered.map((p) => String(storedParts.find((s) => Number(s.partNumber) === Number(p.partNumber)).etag).replace(/"/g, '')))
        const versions = bucket.versioning === 'enabled'

        const result = await this.repo.transaction(async (tx) => {
            const parentId = await this.ensurePrefixes(tx, bucket, key, actor)
            const name = util.basename(key)
            let node = await tx.findOne('directory', { bucketId: bucket.id, parentId, name })
            let versionNumber = 1
            let replaced = null
            if (node) {
                if (node.latestVersionId) {
                    const latest = await tx.findOne('object_version', { id: node.latestVersionId })
                    if (latest) versionNumber = Number(latest.versionNumber) + 1
                }
                if (!versions) replaced = node.latestVersionId
            } else {
                node = await tx.insert('directory', {
                    id: randomUUID(),
                    bucketId: bucket.id,
                    parentId,
                    name,
                    path: key,
                    depth: key.split('/').length,
                    type: 'file',
                    ownerId: upload.ownerId || actor.id || null,
                    createdBy: upload.createdBy || actor.name || null,
                })
            }
            const firstBlock = await tx.get('select "encAlg", "keyId", "wrappedDek" from "block" where "uploadId" = ? and "partNumber" = ? and "ordinal" = 0 limit 1', [uploadId, ordered[0].partNumber])
            if (versions && node.latestVersionId) {
                await tx.update('object_version', { objectId: node.id, isLatest: true }, { isLatest: false })
            }
            await tx.insert('object_version', {
                id: versionId,
                objectId: node.id,
                bucketId: bucket.id,
                path: key,
                versionNumber,
                isLatest: true,
                size: totalSize,
                etag,
                checksum: `md5:${etag}`,
                contentType: upload.contentType,
                metadata: upload.metadata,
                tags: upload.tags,
                storageClass: upload.storageClass,
                tier: this.tierForStorageClass(upload.storageClass),
                encAlg: firstBlock ? firstBlock.encAlg : null,
                keyId: firstBlock ? firstBlock.keyId : null,
                wrappedDek: firstBlock ? firstBlock.wrappedDek : null,
                createdBy: actor.name || upload.createdBy || null,
                ownerId: upload.ownerId || actor.id || null,
            })
            // Move the staged part chunks onto the new version, renumbering the
            // chunks in part order (S3 etag / ordering semantics).
            const staged = await tx.find('block', { uploadId }, {
                orderBy: [{ column: 'partNumber', dir: 'asc' }, { column: 'ordinal', dir: 'asc' }],
            })
            const wanted = new Set(ordered.map((p) => Number(p.partNumber)))
            let ordinal = 0
            for (const row of staged.filter((r) => wanted.has(Number(r.partNumber)))) {
                // eslint-disable-next-line no-await-in-loop
                await tx.update('block', { id: row.id }, {
                    versionId, fileId: node.id, partNumber: null, uploadId: null, ordinal,
                })
                ordinal += 1
            }
            await tx.update('directory', { id: node.id }, {
                size: totalSize,
                etag,
                checksum: `md5:${etag}`,
                contentType: upload.contentType || node.contentType,
                metadata: upload.metadata || node.metadata,
                tags: upload.tags || node.tags,
                storageClass: upload.storageClass,
                latestVersionId: versionId,
                deletedAt: null,
                ownerId: upload.ownerId || node.ownerId,
                updatedAt: now,
            })
            if (replaced) await tx.delete('object_version', { id: replaced })
            await tx.delete('multipart_part', { uploadId })
            await tx.update('multipart_upload', { id: uploadId }, { status: 'completed', completedAt: now })

            return { objectId: node.id, replacedId: replaced }
        })

        if (result.replacedId) await this.purgeVersion({ id: result.replacedId })
        const node = await this.getNodeById(result.objectId)
        this.emit('OBJECT_CREATED', {
            bucket, node, versionId, size: totalSize, actor, multipart: true,
        })
        const versionRow = await this.repo.findOne('object_version', { id: versionId })
        await this.recordAudit('object.put', {
            bucket,
            node,
            version: versionRow,
            actor,
            detail: {
                versionId,
                size: totalSize,
                etag,
                parts: parts.length,
                multipart: true,
                storageClass: upload.storageClass,
                encryption: {
                    enabled: !!versionRow?.encAlg, algorithm: versionRow?.encAlg || null, keyId: versionRow?.keyId || null, envelope: !!versionRow?.wrappedDek,
                },
            },
        })

        return {
            node, versionId, etag, size: totalSize, location: `/${bucket.name}/${key}`,
        }
    }

    /** Abort uploads that were never completed (invoked by the lifecycle worker). */
    async abortStaleUploads(olderThanDays = this.config.multipartTtlDays) {
        const cutoff = util.addDays(new Date(), -olderThanDays)
        const stale = await this.repo.find('multipart_upload', {
            status: 'in-progress', createdAt: { lt: cutoff },
        })
        for (const upload of stale) {
            const bucket = await this.repo.findOne('bucket', { id: upload.bucketId })
            if (!bucket) continue
            // eslint-disable-next-line no-await-in-loop
            await this.abortMultipart(bucket, upload.id).catch(() => {})
        }

        return stale.length
    }

    // ------------------------------------------------------------------
    // Tags / retention / locking
    // ------------------------------------------------------------------

    normalizeTags(tags) {
        if (!tags || typeof tags !== 'object') return null
        const entries = Object.entries(tags).slice(0, MAX_TAGS)
        if (Object.keys(tags).length > MAX_TAGS) throw errors.invalidTag(`An object may have at most ${MAX_TAGS} tags`)

        return Object.fromEntries(entries.map(([k, v]) => [String(k), String(v ?? '')]))
    }

    async getTags(bucket, path) {
        const node = await this.getNode(bucket.id, path)
        if (!node) throw errors.noSuchKey(path)

        return node.tags || {}
    }

    async setTags(bucket, path, tags, actor = {}, versionId) {
        const node = await this.getNode(bucket.id, path)
        if (!node) throw errors.noSuchKey(path)
        const normalized = this.normalizeTags(tags) || {}
        await this.repo.transaction(async (tx) => {
            await tx.update('directory', { id: node.id }, { tags: normalized })
            if (versionId || node.latestVersionId) {
                await tx.update('object_version', { id: versionId || node.latestVersionId }, { tags: normalized })
            }
        })
        if (this.tagger) await this.tagger.indexTags(node.id, bucket.id, normalized).catch(() => {})
        this.emit('OBJECT_TAGGING', {
            bucket, node, actor, tags: normalized,
        })
        await this.recordAudit('object.tagging', {
            bucket, node, actor, detail: { tags: normalized, versionId: versionId || node.latestVersionId },
        })

        return normalized
    }

    async deleteTags(bucket, path, actor = {}) {
        return this.setTags(bucket, path, {}, actor)
    }

    async setRetention(bucket, path, { mode, retainUntil, legalHold }, actor = {}, versionId) {
        if (!bucket.objectLockEnabled) throw errors.invalidRequest('Object Lock is not enabled for this bucket')
        const node = await this.getNode(bucket.id, path)
        if (!node) throw errors.noSuchKey(path)
        if (mode && !['GOVERNANCE', 'COMPLIANCE'].includes(mode)) throw errors.invalidArgument(`Invalid retention mode ${mode}`)
        const until = retainUntil ? new Date(retainUntil) : null
        if (mode && !until) throw errors.invalidArgument('RetainUntilDate is required with a retention mode')
        const patch = {}
        if (mode !== undefined) patch.lockMode = mode
        if (until) patch.lockUntil = until
        if (legalHold !== undefined) patch.legalHold = !!legalHold
        await this.repo.transaction(async (tx) => {
            await tx.update('directory', { id: node.id }, patch)
            if (versionId || node.latestVersionId) {
                const versionPatch = { ...patch }
                if (patch.lockMode) versionPatch.retentionMode = patch.lockMode
                if (patch.lockUntil) versionPatch.retainUntil = patch.lockUntil
                delete versionPatch.lockMode
                delete versionPatch.lockUntil
                await tx.update('object_version', { id: versionId || node.latestVersionId }, versionPatch)
            }
        })

        const updated = await this.getNodeById(node.id)
        await this.recordAudit('object.retention', {
            bucket,
            node: updated,
            actor,
            detail: {
                mode: updated.lockMode, retainUntil: util.iso(updated.lockUntil), legalHold: !!updated.legalHold, versionId: versionId || node.latestVersionId,
            },
        })

        return updated
    }

    async setLegalHold(bucket, path, hold, actor = {}) {
        const updated = await this.setRetention(bucket, path, { legalHold: hold }, actor)
        await this.recordAudit('object.legal_hold', {
            bucket, node: updated, actor, detail: { legalHold: !!hold },
        })

        return updated
    }

    async getRetention(bucket, path, versionId) {
        const { node, version } = await this.getVersion(bucket, path, versionId)

        return {
            mode: version.retentionMode || node.lockMode || null,
            retainUntil: version.retainUntil || node.lockUntil || null,
            legalHold: !!(version.legalHold ?? node.legalHold),
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    tierForStorageClass(storageClass) {
        const map = {
            STANDARD: 'HOT',
            STANDARD_IA: 'COOL',
            ONEZONE_IA: 'COOL',
            INTELLIGENT_TIERING: 'HOT',
            GLACIER: 'ARCHIVE',
            GLACIER_IR: 'ARCHIVE',
            DEEP_ARCHIVE: 'ARCHIVE',
        }

        return map[storageClass] || 'HOT'
    }

    async onVersionWritten({ bucket, node, versionId, size, actor, encryption }) {
        this.metrics?.inc('ddrive_bytes_written_total', size, { bucket: bucket.name })
        this.metrics?.inc('ddrive_objects_written_total', 1, { bucket: bucket.name })
        this.emit('OBJECT_CREATED', {
            bucket, node, versionId, size, actor, encryption,
        })
    }

    emit(type, payload) {
        if (!this.events) return
        this.events.emit(type, payload).catch((err) => this.logger.warn?.({ err, type }, 'event emit failed'))
    }

    /**
     * Compliance audit trail for every data plane change.
     *
     * Each entry carries the encryption state of the version it touched, which
     * is what turns the log into an *encryption* audit log: an operator can
     * prove that a version was written, by whom, and whether it was encrypted
     * (plus the key id when a KMS/BYOK hierarchy is in use).
     */
    async recordAudit(action, opts = {}) {
        if (!this.audit) return
        const {
            bucket, node, version, actor, detail = {}, result = 'success',
        } = opts
        await this.audit.record({
            action,
            actor: actor?.name || 'system',
            actorId: actor?.id || null,
            actorType: actor?.type || (actor?.name ? 'user' : 'system'),
            protocol: actor?.protocol || 'internal',
            bucket: bucket ? bucket.name : null,
            bucketId: bucket ? bucket.id : null,
            objectKey: node?.path || version?.path || opts.objectKey || null,
            versionId: version?.id || detail.versionId || null,
            ip: actor?.ip,
            userAgent: actor?.userAgent,
            requestId: actor?.requestId,
            result,
            detail,
        }).catch((err) => this.logger.debug?.({ err, action }, 'audit record failed'))
    }

    /** Encryption summary for a written version (used by recordAudit). */
    encryptionDetail(written) {
        if (!written) return { enabled: false }
        if (!written.encrypted) return { enabled: false }

        return {
            enabled: true, algorithm: written.encAlg || 'aes-256-gcm', keyId: written.keyId || null, envelope: !!written.wrappedDek,
        }
    }

    /** Stats used by the console dashboard. */
    async stats(bucket) {
        const [objects, bytes, versions, dirs] = await Promise.all([
            this.repo.count('directory', { bucketId: bucket.id, type: 'file', deletedAt: null }),
            this.repo.aggregate('directory', 'sum', 'size', { bucketId: bucket.id, type: 'file', deletedAt: null }),
            this.repo.count('object_version', { bucketId: bucket.id }),
            this.repo.count('directory', { bucketId: bucket.id, type: 'directory' }),
        ])
        const tiers = await this.repo.all(
            'select "tier", count(*) as count, coalesce(sum("size"), 0) as bytes from "block" where "versionId" in (select "id" from "object_version" where "bucketId" = ?) group by "tier"',
            [bucket.id],
        )

        return {
            objects: Number(objects || 0),
            bytes: Number(bytes || 0),
            versions: Number(versions || 0),
            directories: Number(dirs || 0),
            tiers: tiers.map((t) => ({ tier: t.tier, count: Number(t.count), bytes: Number(t.bytes) })),
        }
    }
}

module.exports = { Objects, INTERNAL, prefixPaths, isLockedNow }
