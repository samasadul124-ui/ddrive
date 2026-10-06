/**
 * REST API.
 *
 * Three groups of routes share one namespace:
 *   1. v4 compatible panel routes (`/api/directories`, `/api/files/...`) so the
 *      existing web panel keeps working untouched against the default bucket.
 *   2. v5 object/bucket API (`/api/buckets/...`) with versions, tags, retention,
 *      shares, replication and tiering.
 *   3. Admin API (`/api/admin/...`): users, roles, policies, access keys, audit,
 *      lifecycle, tiering, replication, events, settings, metrics and search.
 *
 * Authentication: Basic (panel + API), Bearer session token (console SPA) or
 * AWS SigV4 (S3 style API keys) - all handled by servers/auth.js.
 */
const { Readable } = require('stream')
const util = require('../lib/util')
const { errors } = require('../lib/errors')
const totp = require('../lib/totp')
const sigv4 = require('../lib/sigv4')

const createRestServer = (context, deps) => {
    const {
        iam, buckets, objects, repo, audit, shares, tagger, lifecycle, tiering, replication, events, metrics, config, logger, health, crypto,
    } = context
    const { auth } = deps
    const defaultBucketName = () => config.node.defaultBucket

    const actorOf = (req) => ({
        id: req.ddrive.principal?.id || null,
        name: req.ddrive.principal?.name || 'anonymous',
        type: req.ddrive.principal?.type || 'anonymous',
        protocol: 'rest',
        ip: req.ddrive.ip,
        requestId: req.id,
    })

    // ------------------------------------------------------------------
    // Router
    // ------------------------------------------------------------------
    const routes = []
    const route = (method, pattern, options, handler) => {
        const patterns = [].concat(pattern)
        const methods = [].concat(method)
        patterns.forEach((single) => routes.push({
            methods, pattern: single, options: options || {}, handler,
        }))
    }

    const matchRoute = (r, url, method) => {
        if (!r.methods.includes(method)) return null
        const routeParts = r.pattern.split('/').filter(Boolean)
        const urlParts = url.split('/').filter(Boolean)
        const params = {}
        let cursor = 0
        for (let i = 0; i < routeParts.length; i += 1) {
            const part = routeParts[i]
            const tail = routeParts.length - i - 1
            if (part === '*') {
                const take = urlParts.length - cursor - tail
                if (take < 1) return null
                params['*'] = urlParts.slice(cursor, cursor + take).map((p) => util.decodeURIComponentSafe(p)).join('/')
                cursor += take
                continue
            }
            const value = urlParts[cursor]
            if (value === undefined) return null
            if (part.startsWith(':')) params[part.slice(1)] = util.decodeURIComponentSafe(value)
            else if (part !== value) return null
            cursor += 1
        }
        if (cursor !== urlParts.length) return null

        return params
    }

    const specificity = (r) => r.pattern.split('/').filter(Boolean).length * 10 - (r.pattern.includes('*') ? 1 : 0)

    /** Wrap a handler with authentication + authorization. */
    const guard = (action, resourceFn, handler) => async (req, reply, params, principal) => {
        const user = principal || await auth.requirePrincipal(req, reply)
        req.ddrive.principal = user
        const resource = typeof resourceFn === 'function' ? await resourceFn(req, params) : (resourceFn || {})
        if (action) await auth.authorize(req, user, action, resource)

        return handler(req, reply, params, user)
    }

    const json = (req, reply, body, statusCode = 200) => {
        reply.code(statusCode)

        return reply.send(body)
    }

    // ------------------------------------------------------------------
    // Serialization helpers
    // ------------------------------------------------------------------
    const encodePath = (path) => String(path || '').split('/').map((part) => encodeURIComponent(part)).join('/')

    const objectJson = (bucket, node, extra = {}) => {
        if (!node) return null

        return {
            id: node.id,
            name: node.name,
            path: node.path,
            key: node.path,
            bucket: bucket ? bucket.name : null,
            type: node.type,
            size: Number(node.size || 0),
            etag: node.etag || null,
            contentType: node.contentType || null,
            storageClass: node.storageClass || 'STANDARD',
            metadata: node.metadata || null,
            tags: node.tags || {},
            createdAt: util.iso(node.createdAt),
            updatedAt: util.iso(node.updatedAt),
            createdBy: node.createdBy || null,
            versionId: node.latestVersionId || null,
            legalHold: !!node.legalHold,
            retentionMode: node.lockMode || null,
            retainUntil: util.iso(node.lockUntil),
            replicationStatus: node.replicationStatus || 'none',
            url: bucket && node.path ? `/api/buckets/${encodeURIComponent(bucket.name)}/objects/${encodePath(node.path)}` : null,
            downloadUrl: bucket && node.path ? `/api/buckets/${encodeURIComponent(bucket.name)}/objects/${encodePath(node.path)}/download` : null,
            ...extra,
        }
    }

    const bucketJson = async (bucket, { stats = true } = {}) => ({
        name: bucket.name,
        id: bucket.id,
        region: bucket.region,
        versioning: bucket.versioning,
        objectLockEnabled: !!bucket.objectLockEnabled,
        defaultRetentionMode: bucket.defaultRetentionMode || null,
        defaultRetentionDays: bucket.defaultRetentionDays === null || bucket.defaultRetentionDays === undefined ? null : Number(bucket.defaultRetentionDays),
        defaultLegalHold: !!bucket.defaultLegalHold,
        defaultStorageClass: bucket.defaultStorageClass || 'STANDARD',
        quotaBytes: bucket.quotaBytes === null || bucket.quotaBytes === undefined ? null : Number(bucket.quotaBytes),
        tags: bucket.tags || {},
        createdAt: util.iso(bucket.createdAt),
        createdBy: bucket.createdBy || null,
        ownerId: bucket.ownerId || null,
        ...(stats ? { stats: await objects.stats(bucket) } : {}),
    })

    const requireBucket = async (name) => {
        if (!name) throw errors.noSuchBucket(name)
        const bucket = await buckets.get(name)

        return bucket
    }

    /** Object routes arrive as `<key>/<suffix>` - split the known suffixes off. */
    const objectTarget = (params) => {
        const raw = params['*'] || ''
        const suffixes = ['download', 'versions', 'tags', 'retention', 'legal-hold', 'presign', 'parts', 'complete', 'acl']
        const parts = raw.split('/')
        const last = parts[parts.length - 1]
        if (parts.length > 1 && suffixes.includes(last)) {
            return { key: parts.slice(0, -1).join('/'), suffix: last }
        }

        return { key: raw, suffix: null }
    }

    // ==================================================================
    // Session / console
    // ==================================================================
    route('POST', '/api/login', { anon: true }, async (req, reply) => {
        const { username, password, mfaCode } = req.body || {}
        if (!username || !password) throw errors.validation('username and password are required')
        const user = await iam.verifyPassword(username, password)
        if (!user) {
            await audit.record({
                action: 'iam.login', actor: username, actorType: 'user', result: 'denied', protocol: 'console', ip: req.ddrive.ip, requestId: req.id,
            })

            throw errors.accessDenied('Invalid username or password')
        }
        if (user.mfaEnabled) {
            if (!mfaCode) throw errors.validation('MFA code required')
            if (!totp.verifyTotp(user.mfaSecret, mfaCode)) throw errors.accessDenied('Invalid MFA code')
        }
        const principal = await iam.buildPrincipal(user)
        const token = auth.issueSession(user)
        await audit.record({
            action: 'iam.login', actor: user.username, actorId: user.id, actorType: 'user', result: 'success', protocol: 'console', ip: req.ddrive.ip, requestId: req.id,
        })
        reply.header('set-cookie', `ddrive_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200${req.ddrive.secure ? '; Secure' : ''}`)

        return json(req, reply, { token, user: { ...principal, isAdmin: !!user.isAdmin }, expiresIn: 43200 })
    })

    route('POST', '/api/logout', { anon: true }, async (req, reply) => {
        reply.header('set-cookie', 'ddrive_session=; Path=/; HttpOnly; Max-Age=0')

        return json(req, reply, { ok: true })
    })

    route('GET', '/api/me', { action: null }, async (req, reply, params, principal) => json(req, reply, {
        user: principal,
        buckets: (await buckets.list()).map((b) => b.name),
        capabilities: {
            publicAccess: config.security.publicAccess,
            webdav: config.servers.webdav.enabled,
            s3: config.servers.s3.enabled,
            aiTagger: { enabled: !!config.ai.url },
            version: context.VERSION,
            defaultBucket: config.node.defaultBucket,
        },
    }))

    route('POST', '/api/me/password', {}, async (req, reply, params, principal) => {
        const { currentPassword, newPassword } = req.body || {}
        if (!principal.id) throw errors.accessDenied('Not a user session')
        const user = await repo.findOne('user', { id: principal.id })
        if (!user) throw errors.accessDenied('User no longer exists')
        if (!crypto.verifyPassword(currentPassword || '', user.passwordHash, user.passwordSalt)) throw errors.accessDenied('Current password is incorrect')
        iam.assertPassword(newPassword, user.username)
        const hashed = crypto.hashPassword(newPassword)
        await repo.update('user', { id: user.id }, { passwordHash: hashed.hash, passwordSalt: hashed.salt, mustChangePassword: false })

        return json(req, reply, { ok: true })
    })

    route('POST', '/api/me/mfa', {}, async (req, reply, params, principal) => {
        const user = await repo.findOne('user', { id: principal.id })
        if (!user) throw errors.accessDenied('User no longer exists')
        const secret = totp.generateSecret()
        await repo.update('user', { id: user.id }, { mfaSecret: secret, mfaEnabled: false })

        return json(req, reply, {
            secret,
            uri: totp.provisioningUri({ secret, account: user.username }),
            hint: 'POST /api/me/mfa/verify with a code to activate',
        })
    })

    route('POST', '/api/me/mfa/verify', {}, async (req, reply, params, principal) => {
        const user = await repo.findOne('user', { id: principal.id })
        if (!user || !user.mfaSecret) throw errors.validation('No MFA secret provisioned')
        if (!totp.verifyTotp(user.mfaSecret, req.body?.code)) throw errors.accessDenied('Invalid MFA code')
        await repo.update('user', { id: user.id }, { mfaEnabled: true })

        return json(req, reply, { enabled: true })
    })

    route('DELETE', '/api/me/mfa', {}, async (req, reply, params, principal) => {
        await repo.update('user', { id: principal.id }, { mfaEnabled: false, mfaSecret: null })

        return json(req, reply, { enabled: false })
    })

    // ==================================================================
    // v4 compatible panel API (default bucket)
    // ==================================================================
    const rootDirectory = async () => {
        const bucket = await buckets.get(defaultBucketName())

        return { bucket, node: { id: bucket.id, name: bucket.name, path: '', parentId: null, type: 'directory', createdAt: bucket.createdAt } }
    }

    const resolveLegacyDirectory = async (id) => {
        const { bucket } = await rootDirectory()
        if (!id || id === 'root' || id === bucket.id || id === '1') return { bucket, node: null, parentId: null }
        const node = await repo.findOne('directory', { id, bucketId: bucket.id })
        if (!node) {
            // legacy numeric ids from ddrive 4.x: treat as the bucket root
            if (/^\d+$/.test(String(id))) return { bucket, node: null, parentId: null }
            throw errors.noSuchKey(id)
        }
        if (node.type !== 'directory') throw errors.noSuchKey(id)
        const parent = node.parentId ? await repo.findOne('directory', { id: node.parentId }) : null

        return {
            bucket, node, parentId: node.parentId || bucket.id, parentPath: parent ? parent.path : '',
        }
    }

    const legacyNodeJson = (bucket, node) => ({
        id: node.id,
        name: node.name,
        size: Number(node.size || 0),
        type: node.type === 'directory' ? 'directory' : 'file',
        createdAt: util.iso(node.createdAt),
        updatedAt: util.iso(node.updatedAt),
        url: node.type === 'file' ? `/api/files/${node.id}/download` : null,
        parentId: node.parentId || bucket.id,
    })

    route('GET', ['/api/directories', '/api/directories/*'], {}, async (req, reply, params, principal) => {
        const id = params['*'] ? params['*'].split('/')[0] : null
        const { bucket, node, parentId } = await resolveLegacyDirectory(id)
        await auth.authorize(req, principal, 's3:ListBucket', { bucket: bucket.name })
        const path = node ? node.path : ''
        const children = await objects.children(bucket, path)
        const directories = children.filter((c) => c.type === 'directory' && !c.deletedAt)
        const files = children.filter((c) => c.type === 'file' && !c.deletedAt)

        return json(req, reply, {
            id: node ? node.id : bucket.id,
            name: node ? node.name : bucket.name,
            path,
            parentId: parentId === null ? null : (node ? parentId : null),
            createdAt: util.iso(node ? node.createdAt : bucket.createdAt),
            child: {
                directories: directories.map((c) => legacyNodeJson(bucket, c)),
                files: files.map((c) => legacyNodeJson(bucket, c)),
            },
        })
    })

    route('POST', '/api/directories', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        await auth.authorize(req, principal, 's3:PutObject', { bucket: bucket.name })
        const { name, parentId } = req.body || {}
        if (!name || !String(name).trim()) throw errors.validation('name is required')
        const parent = parentId && parentId !== bucket.id ? await repo.findOne('directory', { id: parentId, bucketId: bucket.id }) : null
        const path = parent && parent.path ? `${parent.path}/${String(name).trim()}` : String(name).trim()
        const created = await objects.createDirectory(bucket, path, { actor: actorOf(req) })

        return json(req, reply, legacyNodeJson(bucket, created), 201)
    })

    route('PUT', '/api/directories/:id', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        const { node } = await resolveLegacyDirectory(params.id)
        if (!node) throw errors.validation('Cannot rename the root directory')
        await auth.authorize(req, principal, 's3:PutObject', { bucket: bucket.name })
        const { name, parentId } = req.body || {}
        const parent = parentId && parentId !== bucket.id ? await repo.findOne('directory', { id: parentId, bucketId: bucket.id }) : null
        const targetParent = parent ? parent.path : util.parentPath(node.path)
        const newPath = targetParent ? `${targetParent}/${name || node.name}` : (name || node.name)
        if (newPath !== node.path) {
            const moved = await objects.move(bucket, node.path, newPath, { actor: actorOf(req), overwrite: false })

            return json(req, reply, legacyNodeJson(bucket, moved.node || moved))
        }

        return json(req, reply, legacyNodeJson(bucket, node))
    })

    route('DELETE', '/api/directories/:id', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        const { node } = await resolveLegacyDirectory(params.id)
        if (!node) throw errors.conflict('Cannot delete the bucket root through the panel')
        await auth.authorize(req, principal, 's3:DeleteObject', { bucket: bucket.name })
        await objects.deleteDirectory(bucket, node.path, { actor: actorOf(req), recursive: true })
        reply.code(204)

        return reply.send('')
    })

    route('GET', '/api/files/:id', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        await auth.authorize(req, principal, 's3:GetObject', { bucket: bucket.name })
        const node = await repo.findOne('directory', { id: params.id, bucketId: bucket.id })
        if (!node || node.type !== 'file') throw errors.noSuchKey(params.id)

        return json(req, reply, legacyNodeJson(bucket, node))
    })

    route('PUT', '/api/files/:id', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        await auth.authorize(req, principal, 's3:PutObject', { bucket: bucket.name })
        const node = await repo.findOne('directory', { id: params.id, bucketId: bucket.id })
        if (!node || node.type !== 'file') throw errors.noSuchKey(params.id)
        const { name, parentId } = req.body || {}
        const parent = parentId && parentId !== bucket.id ? await repo.findOne('directory', { id: parentId, bucketId: bucket.id }) : null
        const targetParent = parent ? parent.path : util.parentPath(node.path)
        const newPath = targetParent ? `${targetParent}/${name || node.name}` : (name || node.name)
        if (newPath !== node.path) {
            const moved = await objects.move(bucket, node.path, newPath, { actor: actorOf(req) })

            return json(req, reply, legacyNodeJson(bucket, moved.node || moved))
        }

        return json(req, reply, legacyNodeJson(bucket, node))
    })

    route('DELETE', '/api/files/:id', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        await auth.authorize(req, principal, 's3:DeleteObject', { bucket: bucket.name })
        const node = await repo.findOne('directory', { id: params.id, bucketId: bucket.id })
        if (!node) {
            reply.code(204)

            return reply.send('')
        }
        await objects.deleteObject({
            bucket, path: node.path, permanent: true, actor: actorOf(req),
        })
        reply.code(204)

        return reply.send('')
    })

    route('POST', '/api/files/:id', {}, async (req, reply, params, principal) => {
        const { bucket, node: parentNode } = await resolveLegacyDirectory(params.id)
        await auth.authorize(req, principal, 's3:PutObject', { bucket: bucket.name })
        const data = await req.file({ limits: { fileSize: Infinity } })
        if (!data) throw errors.validation('file is missing in the request body')
        const parentPath = parentNode ? parentNode.path : ''
        const path = parentPath ? `${parentPath}/${data.filename}` : data.filename
        const result = await objects.putObject({
            bucket,
            path,
            stream: data.file,
            contentType: data.mimetype || util.contentTypeOf(data.filename),
            actor: actorOf(req),
        })

        return json(req, reply, legacyNodeJson(bucket, result.node), 201)
    })

    route('GET', '/api/files/:id/download', {}, async (req, reply, params, principal) => {
        const { bucket } = await rootDirectory()
        await auth.authorize(req, principal, 's3:GetObject', { bucket: bucket.name })
        const node = await repo.findOne('directory', { id: params.id, bucketId: bucket.id })
        if (!node || node.type !== 'file') throw errors.noSuchKey(params.id)
        const version = await repo.findOne('object_version', { id: node.latestVersionId })
        const range = req.headers.range ? util.parseRange(req.headers.range, Number(version.size)) : null
        const result = await objects.stream(version, range)
        reply.code(range ? 206 : 200)
        reply.header('content-type', version.contentType || util.contentTypeOf(node.name))
        reply.header('etag', `"${node.etag}"`)
        reply.header('accept-ranges', 'bytes')
        reply.header('content-disposition', util.contentDisposition(node.name, 'attachment'))
        if (range) {
            reply.header('content-range', `bytes ${range.start}-${range.end}/${version.size}`)
            reply.header('content-length', String(range.length))
        } else {
            reply.header('content-length', String(version.size))
        }
        await objects.recordAccess(version, range ? range.length : version.size)

        return reply.send(result.stream)
    })

    // ==================================================================
    // Buckets
    // ==================================================================
    route('GET', '/api/buckets', {}, guard('s3:ListAllMyBuckets', {}, async (req, reply) => {
        const list = await buckets.list()
        const out = await Promise.all(list.map((bucket) => bucketJson(bucket)))

        return json(req, reply, { buckets: out })
    }))

    route('POST', '/api/buckets', {}, guard(null, {}, async (req, reply, params, principal) => {
        const { name, region, versioning, objectLockEnabled, quotaBytes, defaultStorageClass } = req.body || {}
        await auth.authorize(req, principal, 's3:CreateBucket', { bucket: name })
        const bucket = await buckets.create(name, {
            region, versioning, objectLockEnabled, quotaBytes, defaultStorageClass, ownerId: principal.id, createdBy: principal.name,
        })
        await audit.record({
            action: 'rest.CreateBucket', actor: principal.name, actorId: principal.id, bucket: bucket.name, bucketId: bucket.id, protocol: 'rest', ip: req.ddrive.ip, requestId: req.id, result: 'success',
        })

        return json(req, reply, await bucketJson(bucket, { stats: false }), 201)
    }))

    route('GET', '/api/buckets/:bucket', {}, guard('s3:ListBucket', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const body = await bucketJson(bucket)
        body.policy = await buckets.getPolicy(bucket.name).catch(() => null)
        body.posture = await buckets.posture(bucket.name)
        body.lifecycleRules = await lifecycle.listRules(bucket)
        body.tieringPolicies = await tiering.listPolicies(bucket)

        return json(req, reply, body)
    }))

    route('PATCH', '/api/buckets/:bucket', {}, guard('s3:PutBucketVersioning', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const patch = { ...(req.body || {}) }
        if (patch.policy !== undefined) {
            await buckets.setPolicy(params.bucket, patch.policy, { name: req.ddrive.principal.name })
            delete patch.policy
        }
        if (patch.objectLockEnabled && !Object.keys(patch).some((k) => k !== 'objectLockEnabled')) {
            const bucket = await requireBucket(params.bucket)
            if (!bucket.objectLockEnabled) await buckets.setObjectLock(params.bucket, { enabled: true, mode: patch.defaultRetentionMode, days: patch.defaultRetentionDays })
        }
        const updated = await buckets.update(params.bucket, patch)

        return json(req, reply, {
            ...(await bucketJson(updated, { stats: false })),
            policy: await buckets.getPolicy(updated.name).catch(() => null),
        })
    }))

    route('DELETE', '/api/buckets/:bucket', {}, guard('s3:DeleteBucket', (req, p) => ({ bucket: p.bucket }), async (req, reply, params, principal) => {
        const force = String(req.query.force || '') === 'true'
        await buckets.remove(params.bucket, { force, actor: principal.name })
        reply.code(204)

        return reply.send('')
    }))

    // ==================================================================
    // Objects
    // ==================================================================
    route('GET', '/api/buckets/:bucket/objects', {}, guard('s3:ListBucket', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const prefix = req.query.prefix || ''
        const recursive = String(req.query.recursive || '') === 'true'
        const delimiter = recursive ? '' : (req.query.delimiter === undefined ? '/' : req.query.delimiter)
        const result = await objects.list({
            bucket,
            prefix,
            delimiter,
            startAfter: req.query.startAfter || '',
            maxKeys: Math.min(Number(req.query.limit || config.security.maxKeys), config.security.maxKeys),
            includeDirectories: delimiter === '' && String(req.query.includeDirectories || '') === 'true',
        })

        return json(req, reply, {
            prefix,
            delimiter,
            objects: (result.contents || []).map((node) => objectJson(bucket, node)),
            prefixes: result.commonPrefixes || [],
            isTruncated: !!result.isTruncated,
            nextMarker: result.nextMarker || null,
        })
    }))

    route('POST', '/api/buckets/:bucket/objects', {}, guard('s3:PutObject', (req, p) => ({ bucket: p.bucket }), async (req, reply, params, principal) => {
        const bucket = await requireBucket(params.bucket)
        const data = await req.file({ limits: { fileSize: Infinity } })
        if (!data) throw errors.validation('file is missing in the request body')
        const path = req.query.path || data.filename
        const result = await objects.putObject({
            bucket,
            path,
            stream: data.file,
            contentType: data.mimetype || util.contentTypeOf(path),
            tags: req.query.tags ? JSON.parse(req.query.tags) : null,
            actor: actorOf(req),
        })

        return json(req, reply, objectJson(bucket, result.node, { versionId: result.versionId, etag: result.etag }), 201)
    }))

    route('PUT', '/api/buckets/:bucket/objects/*', {}, guard(null, (req, p) => ({ bucket: p.bucket, key: objectTarget(p).key }), async (req, reply, params, principal) => {
        const bucket = await requireBucket(params.bucket)
        const { key, suffix } = objectTarget(params)
        if (suffix === 'tags') {
            await auth.authorize(req, principal, 's3:PutObjectTagging', { bucket: bucket.name, key })
            const tags = await objects.setTags(bucket, key, req.body?.tags || req.body || {}, actorOf(req), req.query.versionId)

            return json(req, reply, { tags })
        }
        if (suffix === 'retention') {
            await auth.authorize(req, principal, 's3:PutObjectRetention', { bucket: bucket.name, key })
            await objects.setRetention(bucket, key, {
                mode: req.body?.mode,
                retainUntil: req.body?.retainUntil ? new Date(req.body.retainUntil) : null,
                legalHold: req.body?.legalHold,
            }, actorOf(req), req.query.versionId)
            await audit.record({
                action: 'rest.PutObjectRetention', actor: principal.name, actorId: principal.id, bucket: bucket.name, objectKey: key, protocol: 'rest', detail: req.body, result: 'success',
            })
            const retention = await objects.getRetention(bucket, key, req.query.versionId)

            return json(req, reply, { ...retention, retainUntil: util.iso(retention.retainUntil) })
        }
        if (suffix === 'legal-hold') {
            await auth.authorize(req, principal, 's3:PutObjectLegalHold', { bucket: bucket.name, key })
            await objects.setLegalHold(bucket, key, !!req.body?.hold, actorOf(req))

            return json(req, reply, { legalHold: !!req.body?.hold })
        }
        if (suffix) throw errors.methodNotAllowed(`PUT is not supported on ${suffix}`)
        await auth.authorize(req, principal, 's3:PutObject', { bucket: bucket.name, key })
        const result = await objects.putObject({
            bucket,
            path: key,
            stream: util.bodyStream(req),
            contentType: req.headers['content-type'] || util.contentTypeOf(key),
            storageClass: req.headers['x-ddrive-storage-class'] || undefined,
            metadata: req.headers['x-ddrive-metadata'] ? JSON.parse(req.headers['x-ddrive-metadata']) : undefined,
            actor: actorOf(req),
        })
        reply.header('etag', `"${result.etag}"`)

        return json(req, reply, objectJson(bucket, result.node, { versionId: result.versionId }), 201)
    }))

    route('POST', '/api/buckets/:bucket/objects/*', {}, guard(null, (req, p) => ({ bucket: p.bucket, key: objectTarget(p).key }), async (req, reply, params, principal) => {
        const bucket = await requireBucket(params.bucket)
        const { key, suffix } = objectTarget(params)
        await auth.authorize(req, principal, 's3:PutObject', { bucket: bucket.name, key })
        if (suffix === 'presign') {
            const expiresIn = Math.min(Number(req.body?.expiresIn || 3600), config.security.presignMaxExpiry)
            const url = presignUrl(req, bucket.name, key, expiresIn, principal)

            return json(req, reply, { url, expiresIn })
        }
        throw errors.methodNotAllowed(`POST is not supported on ${suffix || key}`)
    }))

    route('GET', '/api/buckets/:bucket/objects/*', {}, guard(null, (req, p) => ({ bucket: p.bucket, key: objectTarget(p).key }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const { key, suffix } = objectTarget(params)
        if (suffix === 'download') return downloadObject(req, reply, bucket, key)
        if (suffix === 'versions') {
            await auth.authorize(req, req.ddrive.principal, 's3:ListBucketVersions', { bucket: bucket.name, key })
            const node = await objects.getNode(bucket.id, key)
            if (!node) throw errors.noSuchKey(key)
            const versions = await repo.find('object_version', { objectId: node.id }, { orderBy: [{ column: 'versionNumber', dir: 'desc' }] })

            return json(req, reply, {
                path: key,
                versions: versions.map((v) => ({
                    versionId: v.id,
                    versionNumber: Number(v.versionNumber),
                    isLatest: !!v.isLatest,
                    isDeleteMarker: !!v.isDeleteMarker,
                    size: Number(v.size || 0),
                    etag: v.etag,
                    storageClass: v.storageClass,
                    tier: v.tier,
                    encrypted: !!v.encAlg,
                    createdAt: util.iso(v.createdAt),
                    retainedUntil: util.iso(v.retainUntil),
                    legalHold: !!v.legalHold,
                    replicationStatus: v.replicationStatus || 'none',
                    createdBy: v.createdBy,
                })),
            })
        }
        if (suffix === 'tags') {
            await auth.authorize(req, req.ddrive.principal, 's3:GetObjectTagging', { bucket: bucket.name, key })

            return json(req, reply, { tags: await objects.getTags(bucket, key) })
        }
        if (suffix === 'retention') {
            await auth.authorize(req, req.ddrive.principal, 's3:GetObjectRetention', { bucket: bucket.name, key })
            const retention = await objects.getRetention(bucket, key, req.query.versionId)

            return json(req, reply, {
                mode: retention.mode, retainUntil: util.iso(retention.retainUntil), legalHold: !!retention.legalHold, versionId: retention.versionId,
            })
        }
        await auth.authorize(req, req.ddrive.principal, 's3:GetObject', { bucket: bucket.name, key })
        const node = await objects.getNode(bucket.id, key)
        if (!node || (node.type === 'file' && node.deletedAt)) throw errors.noSuchKey(key)
        if (node.type === 'directory') {
            const children = await objects.children(bucket, key)

            return json(req, reply, objectJson(bucket, node, { children: children.map((c) => objectJson(bucket, c)) }))
        }

        return json(req, reply, objectJson(bucket, node))
    }))

    const downloadObject = async (req, reply, bucket, key) => {
        const principal = req.ddrive.principal
        const { node, version } = await objects.getVersion(bucket, key, req.query.versionId)
        await auth.authorize(req, principal, req.query.versionId ? 's3:GetObjectVersion' : 's3:GetObject', { bucket: bucket.name, key })
        const range = req.headers.range ? util.parseRange(req.headers.range, Number(version.size)) : null
        const result = await objects.stream(version, range)
        reply.code(range ? 206 : 200)
        reply.header('content-type', version.contentType || util.contentTypeOf(node.name))
        reply.header('etag', `"${node.etag}"`)
        reply.header('x-ddrive-version-id', version.id)
        reply.header('accept-ranges', 'bytes')
        reply.header('content-disposition', util.contentDisposition(node.name, util.isInlineType(version.contentType) ? 'inline' : 'attachment'))
        if (range) {
            reply.header('content-range', `bytes ${range.start}-${range.end}/${version.size}`)
            reply.header('content-length', String(range.length))
        } else {
            reply.header('content-length', String(version.size))
        }
        await objects.recordAccess(version, range ? range.length : version.size)

        return reply.send(result.stream)
    }

    route('DELETE', '/api/buckets/:bucket/objects/*', {}, guard(null, (req, p) => ({ bucket: p.bucket, key: objectTarget(p).key }), async (req, reply, params, principal) => {
        const bucket = await requireBucket(params.bucket)
        const { key, suffix } = objectTarget(params)
        if (suffix === 'tags') {
            await auth.authorize(req, principal, 's3:DeleteObjectTagging', { bucket: bucket.name, key })
            await objects.deleteTags(bucket, key, actorOf(req))
            reply.code(204)

            return reply.send('')
        }
        if (suffix) throw errors.methodNotAllowed(`DELETE is not supported on ${suffix}`)
        await auth.authorize(req, principal, 's3:DeleteObject', { bucket: bucket.name, key })
        const result = await objects.deleteObject({
            bucket,
            path: key,
            versionId: req.query.versionId,
            permanent: String(req.query.permanent || '') === 'true',
            recursive: String(req.query.recursive || '') === 'true',
            bypassGovernance: String(req.query.bypassGovernance || '') === 'true',
            actor: actorOf(req),
        })

        return json(req, reply, { deleted: true, versionId: result.versionId, deleteMarker: !!result.deleteMarker })
    }))

    // Multipart uploads (large files through the modern API)
    route('POST', '/api/buckets/:bucket/multipart', {}, guard('s3:PutObject', (req, p) => ({ bucket: p.bucket, key: req.body?.path }), async (req, reply, params, principal) => {
        const bucket = await requireBucket(params.bucket)
        const upload = await objects.initiateMultipart({
            bucket,
            path: req.body?.path,
            contentType: req.body?.contentType,
            metadata: req.body?.metadata,
            storageClass: req.body?.storageClass,
            actor: actorOf(req),
        })

        return json(req, reply, { uploadId: upload.id, path: upload.path }, 201)
    }))

    route('PUT', '/api/buckets/:bucket/multipart/:uploadId/parts/:partNumber', {}, guard('s3:PutObject', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const part = await objects.uploadPart(bucket, params.uploadId, Number(params.partNumber), util.bodyStream(req))
        reply.header('etag', `"${part.etag}"`)

        return json(req, reply, { partNumber: Number(part.partNumber), etag: part.etag, size: Number(part.size || 0) })
    }))

    route('POST', '/api/buckets/:bucket/multipart/:uploadId/complete', {}, guard('s3:PutObject', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const parts = (req.body?.parts || []).map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag || '').replace(/"/g, '') }))
        const result = await objects.completeMultipart(bucket, params.uploadId, parts, actorOf(req))

        return json(req, reply, { path: result.path, etag: result.etag, versionId: result.versionId, size: Number(result.size || 0) })
    }))

    route('GET', '/api/buckets/:bucket/multipart/:uploadId', {}, guard('s3:ListMultipartUploadParts', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const result = await objects.listParts(bucket, params.uploadId)

        return json(req, reply, {
            uploadId: params.uploadId,
            parts: result.parts.map((p) => ({
                partNumber: Number(p.partNumber), etag: p.etag, size: Number(p.size || 0), createdAt: util.iso(p.createdAt),
            })),
        })
    }))

    route('DELETE', '/api/buckets/:bucket/multipart/:uploadId', {}, guard('s3:AbortMultipartUpload', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        await objects.abortMultipart(bucket, params.uploadId)
        reply.code(204)

        return reply.send('')
    }))

    route('POST', '/api/buckets/:bucket/objects/*/restore', {}, guard('s3:RestoreObject', (req, p) => ({ bucket: p.bucket, key: objectTarget(p).key }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const { key } = objectTarget(params)
        const { node, version } = await objects.getVersion(bucket, key, req.query.versionId)
        if ((version.tier || 'HOT') === 'HOT') return json(req, reply, { restored: false, tier: 'HOT' })
        await tiering.transitionVersion(bucket, node, version, 'HOT', { reason: 'restore' })

        return json(req, reply, { restored: true, tier: 'HOT' })
    }))

    // ==================================================================
    // Shares
    // ==================================================================
    route('GET', '/api/buckets/:bucket/shares', {}, guard('ddrive:ManageShares', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const list = await shares.list(bucket)

        return json(req, reply, { shares: list.map((s) => ({ ...s, url: `/share/${s.token}` })) })
    }))

    route('POST', '/api/buckets/:bucket/shares', {}, guard('ddrive:ManageShares', (req, p) => ({ bucket: p.bucket, key: req.body?.path }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const {
            path, password, expiresInSeconds, maxDownloads, permission,
        } = req.body || {}
        if (!path) throw errors.validation('path is required')
        const created = await shares.create(bucket, path, {
            password, expiresInSeconds, maxDownloads, permission, actor: actorOf(req),
        })

        return json(req, reply, { ...created, url: `/share/${created.token}` }, 201)
    }))

    route('DELETE', '/api/shares/:token', {}, guard('ddrive:ManageShares', {}, async (req, reply, params, principal) => {
        await shares.revoke(params.token, { id: principal.id, name: principal.name })
        reply.code(204)

        return reply.send('')
    }))

    // ==================================================================
    // Bucket level configuration shortcuts
    // ==================================================================
    route('GET', '/api/buckets/:bucket/lifecycle', {}, guard('s3:GetLifecycleConfiguration', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)

        return json(req, reply, { rules: await lifecycle.listRules(bucket) })
    }))

    route('POST', '/api/buckets/:bucket/lifecycle', {}, guard('s3:PutLifecycleConfiguration', (req, p) => ({ bucket: p.bucket }), async (req, reply, params, principal) => {
        const bucket = await requireBucket(params.bucket)
        const rule = await lifecycle.createRule(bucket, req.body || {}, { name: principal.name })

        return json(req, reply, rule, 201)
    }))

    route('GET', '/api/buckets/:bucket/tiering', {}, guard('ddrive:ManageTiering', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)

        return json(req, reply, { policies: await tiering.listPolicies(bucket), report: await tiering.report(bucket.id) })
    }))

    route('GET', '/api/buckets/:bucket/replication', {}, guard('ddrive:ManageReplication', (req, p) => ({ bucket: p.bucket }), async (req, reply, params) => {
        const bucket = await requireBucket(params.bucket)
        const peers = (await replication.listPeers()).filter((peer) => peer.bucketId === bucket.id || !peer.bucketId)

        return json(req, reply, { peers: peers.map((peer) => ({ ...peer, secretEnc: undefined, secret: undefined })) })
    }))

    // ==================================================================
    // Admin: overview
    // ==================================================================
    const adminOnly = (handler) => async (req, reply, params, principal) => {
        const user = principal || await auth.requirePrincipal(req, reply)
        req.ddrive.principal = user
        if (!user.isAdmin) await auth.authorize(req, user, 'ddrive:ManageUsers', {})

        return handler(req, reply, params, user)
    }

    route('GET', '/api/admin/overview', {}, adminOnly(async (req, reply) => {
        const list = await buckets.list()
        const stats = await Promise.all(list.map((bucket) => objects.stats(bucket)))
        const bucketRows = list.map((bucket, i) => ({
            name: bucket.name,
            region: bucket.region,
            versioning: bucket.versioning,
            objectLockEnabled: !!bucket.objectLockEnabled,
            quotaBytes: bucket.quotaBytes === null || bucket.quotaBytes === undefined ? null : Number(bucket.quotaBytes),
            ...stats[i],
        }))

        return json(req, reply, {
            version: context.VERSION,
            node: { name: config.node.name, region: config.node.region, defaultBucket: config.node.defaultBucket },
            encryption: crypto.enabled
                ? { enabled: true, algorithm: crypto.algorithm, keyId: crypto.keyId, kms: !!config.security.kmsEndpoint }
                : { enabled: false },
            buckets: bucketRows,
            totals: {
                objects: bucketRows.reduce((a, b) => a + b.objects, 0),
                bytes: bucketRows.reduce((a, b) => a + b.bytes, 0),
                versions: bucketRows.reduce((a, b) => a + b.versions, 0),
                buckets: bucketRows.length,
            },
            tiers: await tiering.report(),
            replication: await replication.stats().catch(() => ({ peers: [], byStatus: {} })),
            audit: await audit.stats().catch(() => ({ total: 0 })),
            health: await health(),
            servers: {
                webdav: { enabled: config.servers.webdav.enabled, path: config.servers.webdav.path },
                s3: { enabled: config.servers.s3.enabled, path: config.servers.s3.path, region: config.servers.s3.region },
                console: config.servers.console.enabled,
            },
        })
    }))

    // ==================================================================
    // Admin: users / groups / roles / policies / keys
    // ==================================================================
    route('GET', '/api/admin/users', {}, adminOnly(async (req, reply) => {
        const users = await iam.listUsers()
        const out = []
        for (const user of users) {
            // eslint-disable-next-line no-await-in-loop
            const { roles } = await iam.policiesForUser(user.id)
            out.push({
                id: user.id,
                username: user.username,
                displayName: user.displayName,
                email: user.email,
                status: user.status,
                isAdmin: !!user.isAdmin,
                mfaEnabled: !!user.mfaEnabled,
                mustChangePassword: !!user.mustChangePassword,
                quotaBytes: user.quotaBytes === null || user.quotaBytes === undefined ? null : Number(user.quotaBytes),
                lastLoginAt: util.iso(user.lastLoginAt),
                createdAt: util.iso(user.createdAt),
                roles,
            })
        }

        return json(req, reply, { users: out })
    }))

    route('POST', '/api/admin/users', {}, adminOnly(async (req, reply) => {
        const user = await iam.createUser(req.body || {})
        if (Array.isArray(req.body?.roles)) await iam.setUserRoles(user.id, req.body.roles)

        return json(req, reply, { id: user.id, username: user.username }, 201)
    }))

    route('PATCH', '/api/admin/users/:username', {}, adminOnly(async (req, reply, params) => {
        const user = await iam.updateUser(params.username, req.body || {})
        if (Array.isArray(req.body?.roles)) await iam.setUserRoles(user.id, req.body.roles)

        return json(req, reply, { id: user.id, username: user.username, status: user.status, isAdmin: !!user.isAdmin })
    }))

    route('DELETE', '/api/admin/users/:username', {}, adminOnly(async (req, reply, params) => {
        if (params.username === req.ddrive.principal?.name) throw errors.validation('You cannot delete your own account')
        await iam.deleteUser(params.username)
        reply.code(204)

        return reply.send('')
    }))

    route('GET', '/api/admin/groups', {}, adminOnly(async (req, reply) => json(req, reply, { groups: await iam.listGroups() })))

    route('POST', '/api/admin/groups', {}, adminOnly(async (req, reply) => {
        const group = await iam.createGroup(req.body || {})

        return json(req, reply, group, 201)
    }))

    route('DELETE', '/api/admin/groups/:name', {}, adminOnly(async (req, reply, params) => {
        await iam.deleteGroup(params.name)
        reply.code(204)

        return reply.send('')
    }))

    route('POST', '/api/admin/groups/:name/members', {}, adminOnly(async (req, reply, params) => {
        await iam.addGroupMember(params.name, req.body?.username)

        return json(req, reply, { ok: true }, 201)
    }))

    route('DELETE', '/api/admin/groups/:name/members/:username', {}, adminOnly(async (req, reply, params) => {
        await iam.removeGroupMember(params.name, params.username)
        reply.code(204)

        return reply.send('')
    }))

    route('GET', '/api/admin/roles', {}, adminOnly(async (req, reply) => json(req, reply, { roles: await iam.listRoles() })))
    route('POST', '/api/admin/roles', {}, adminOnly(async (req, reply) => json(req, reply, await iam.createRole(req.body || {}), 201)))
    route('PATCH', '/api/admin/roles/:name', {}, adminOnly(async (req, reply, params) => json(req, reply, await iam.updateRole(params.name, req.body || {}))))
    route('DELETE', '/api/admin/roles/:name', {}, adminOnly(async (req, reply, params) => {
        await iam.deleteRole(params.name)
        reply.code(204)

        return reply.send('')
    }))

    route('GET', '/api/admin/policies', {}, adminOnly(async (req, reply) => json(req, reply, { policies: await iam.listPolicies() })))
    route('POST', '/api/admin/policies', {}, adminOnly(async (req, reply) => json(req, reply, await iam.createPolicy(req.body || {}), 201)))
    route('PUT', '/api/admin/policies/:name', {}, adminOnly(async (req, reply, params) => json(req, reply, await iam.updatePolicy(params.name, req.body?.document || req.body))))
    route('DELETE', '/api/admin/policies/:name', {}, adminOnly(async (req, reply, params) => {
        await iam.deletePolicy(params.name)
        reply.code(204)

        return reply.send('')
    }))

    route('GET', '/api/admin/access-keys', {}, adminOnly(async (req, reply) => {
        const keys = await iam.listAccessKeys(req.query.username)
        const users = await iam.listUsers()
        const byId = new Map(users.map((u) => [u.id, u.username]))

        return json(req, reply, {
            keys: keys.map((k) => ({
                accessKeyId: k.accessKeyId,
                userId: byId.get(k.userId) || k.userId,
                username: byId.get(k.userId) || k.userId,
                description: k.description,
                status: k.status,
                createdAt: util.iso(k.createdAt),
                lastUsedAt: util.iso(k.lastUsedAt),
            })),
        })
    }))

    route('POST', '/api/admin/access-keys', {}, adminOnly(async (req, reply) => {
        const created = await iam.createAccessKey(req.body?.username, { description: req.body?.description, expiresAt: req.body?.expiresAt })

        return json(req, reply, {
            accessKeyId: created.accessKeyId,
            secretAccessKey: created.secretAccessKey,
            warning: 'Store the secret now: it is only shown once.',
        }, 201)
    }))

    route('POST', '/api/admin/access-keys/:accessKeyId/rotate', {}, adminOnly(async (req, reply, params) => json(req, reply, await iam.rotateAccessKey(params.accessKeyId))))

    route('DELETE', '/api/admin/access-keys/:accessKeyId', {}, adminOnly(async (req, reply, params) => {
        await iam.deleteAccessKey(params.accessKeyId)
        reply.code(204)

        return reply.send('')
    }))

    // ==================================================================
    // Admin: audit
    // ==================================================================
    route('GET', '/api/admin/audit', {}, guard('ddrive:ListAudit', {}, async (req, reply) => {
        const eventsResult = await audit.query({
            action: req.query.action,
            actor: req.query.actor,
            bucket: req.query.bucket,
            objectKey: req.query.key || req.query.objectKey,
            result: req.query.result,
            encrypted: req.query.encrypted,
            from: req.query.from,
            to: req.query.to,
            limit: Math.min(Number(req.query.limit || 100), 1000),
            offset: Number(req.query.offset || 0),
        })

        return json(req, reply, {
            events: eventsResult,
            count: eventsResult.length,
        })
    }))

    route('GET', '/api/admin/audit/verify', {}, guard('ddrive:VerifyAudit', {}, async (req, reply) => json(req, reply, await audit.verify())))

    // Encryption roll-up for the compliance report (writes, algorithms, key ids)
    route('GET', '/api/admin/audit/encryption', {}, guard('ddrive:ListAudit', {}, async (req, reply) => json(req, reply, await audit.encryptionSummary({
        bucket: req.query.bucket, from: req.query.from, to: req.query.to,
    }))))

    route('GET', '/api/admin/audit/export', {}, guard('ddrive:ListAudit', {}, async (req, reply) => {
        const csv = await audit.exportCsv({
            limit: 1000,
            action: req.query.action,
            bucket: req.query.bucket,
            actor: req.query.actor,
            result: req.query.result,
            objectKey: req.query.key || req.query.objectKey,
            encrypted: req.query.encrypted,
            from: req.query.from,
            to: req.query.to,
        })
        reply.header('content-type', 'text/csv').header('content-disposition', `attachment; filename="ddrive-audit-${Date.now()}.csv"`)

        return reply.send(csv)
    }))

    // ==================================================================
    // Admin: lifecycle
    // ==================================================================
    route('GET', '/api/admin/lifecycle', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply) => {
        const bucket = req.query.bucket ? await requireBucket(req.query.bucket) : null

        return json(req, reply, { rules: await lifecycle.listRules(bucket) })
    }))

    route('POST', '/api/admin/lifecycle', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply, params, principal) => {
        const bucket = await requireBucket(req.body?.bucket || defaultBucketName())
        const rule = await lifecycle.createRule(bucket, req.body || {}, { name: principal.name })

        return json(req, reply, rule, 201)
    }))

    route('PATCH', '/api/admin/lifecycle/:id', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply, params) => json(req, reply, await lifecycle.updateRule(params.id, req.body || {}))))
    route('DELETE', '/api/admin/lifecycle/:id', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply, params) => {
        await lifecycle.deleteRule(params.id)
        reply.code(204)

        return reply.send('')
    }))

    route('POST', '/api/admin/lifecycle/run', {}, guard('ddrive:RunLifecycle', {}, async (req, reply) => {
        const bucket = req.query.bucket ? await requireBucket(req.query.bucket) : null
        const result = await lifecycle.run({ bucket, dryRun: String(req.query.dryRun || '') === 'true' })

        return json(req, reply, result)
    }))

    // ==================================================================
    // Admin: tiering
    // ==================================================================
    route('GET', '/api/admin/tiering', {}, guard('ddrive:ManageTiering', {}, async (req, reply) => {
        const bucket = req.query.bucket ? await requireBucket(req.query.bucket) : null

        return json(req, reply, { policies: await tiering.listPolicies(bucket), report: await tiering.report(bucket?.id) })
    }))

    route('POST', '/api/admin/tiering', {}, guard('ddrive:ManageTiering', {}, async (req, reply) => {
        const bucket = await requireBucket(req.body?.bucket || defaultBucketName())
        const policy = await tiering.createPolicy(bucket, req.body || {})

        return json(req, reply, policy, 201)
    }))

    route('PATCH', '/api/admin/tiering/:id', {}, guard('ddrive:ManageTiering', {}, async (req, reply, params) => json(req, reply, await tiering.updatePolicy(params.id, req.body || {}))))
    route('DELETE', '/api/admin/tiering/:id', {}, guard('ddrive:ManageTiering', {}, async (req, reply, params) => {
        await tiering.deletePolicy(params.id)
        reply.code(204)

        return reply.send('')
    }))

    route('POST', '/api/admin/tiering/run', {}, guard('ddrive:ManageTiering', {}, async (req, reply) => {
        const bucket = req.query.bucket ? await requireBucket(req.query.bucket) : null

        return json(req, reply, await tiering.run({ bucket, dryRun: String(req.query.dryRun || '') === 'true' }))
    }))

    // ==================================================================
    // Admin: replication
    // ==================================================================
    route('GET', '/api/admin/replication', {}, guard('ddrive:ManageReplication', {}, async (req, reply) => {
        const peers = await replication.listPeers()
        const stats = await replication.stats().catch(() => ({ peers: [], byStatus: {} }))

        return json(req, reply, {
            peers: peers.map((peer) => ({ ...peer, secretEnc: undefined, iv: undefined, authTag: undefined })),
            stats,
        })
    }))

    route('POST', '/api/admin/replication', {}, guard('ddrive:ManageReplication', {}, async (req, reply) => {
        const peer = await replication.createPeer(req.body || {})
        const { secretEnc, iv, authTag, ...safe } = peer

        return json(req, reply, { ...safe, accessKeyId: peer.accessKeyId }, 201)
    }))

    route('PATCH', '/api/admin/replication/:name', {}, guard('ddrive:ManageReplication', {}, async (req, reply, params) => {
        const peer = await replication.updatePeer(params.name, req.body || {})
        const { secretEnc, iv, authTag, ...safe } = peer

        return json(req, reply, safe)
    }))

    route('DELETE', '/api/admin/replication/:name', {}, guard('ddrive:ManageReplication', {}, async (req, reply, params) => {
        await replication.deletePeer(params.name)
        reply.code(204)

        return reply.send('')
    }))

    route('POST', '/api/admin/replication/:name/test', {}, guard('ddrive:ManageReplication', {}, async (req, reply, params) => json(req, reply, await replication.testPeer(params.name))))

    route('POST', '/api/admin/replication/:name/backfill', {}, guard('ddrive:ManageReplication', {}, async (req, reply, params) => {
        const result = await replication.backfill(params.name, {
            bucketId: req.body?.bucketId, actor: actorOf(req), limit: req.body?.limit,
        })

        return json(req, reply, result)
    }))

    route('GET', '/api/admin/replication/tasks', {}, guard('ddrive:ManageReplication', {}, async (req, reply) => {
        const tasks = await repo.find('replication_task', req.query.status ? { status: req.query.status } : {}, {
            orderBy: [{ column: 'createdAt', dir: 'desc' }], limit: Math.min(Number(req.query.limit || 100), 1000),
        })

        return json(req, reply, { tasks })
    }))

    route('POST', '/api/admin/replication/tasks/:id/retry', {}, guard('ddrive:ManageReplication', {}, async (req, reply, params) => {
        await repo.update('replication_task', { id: params.id }, { status: 'pending', attempts: 0, nextAttemptAt: new Date(), lastError: null })

        return json(req, reply, { ok: true })
    }))

    // ==================================================================
    // Admin: events / auto tagging / search / settings / metrics
    // ==================================================================
    route('GET', '/api/admin/events', {}, guard('ddrive:ManageEvents', {}, async (req, reply) => {
        const targets = await events.listTargets()

        return json(req, reply, { targets: targets.map((t) => ({ ...t, secret: t.secret ? '***' : null })) })
    }))

    route('POST', '/api/admin/events', {}, guard('ddrive:ManageEvents', {}, async (req, reply) => {
        const target = await events.createTarget(req.body || {})

        return json(req, reply, { ...target, secret: target.secret ? '***' : null }, 201)
    }))

    route('PATCH', '/api/admin/events/:id', {}, guard('ddrive:ManageEvents', {}, async (req, reply, params) => {
        await events.updateTarget(params.id, req.body || {})

        return json(req, reply, { ok: true })
    }))

    route('DELETE', '/api/admin/events/:id', {}, guard('ddrive:ManageEvents', {}, async (req, reply, params) => {
        await events.deleteTarget(params.id)
        reply.code(204)

        return reply.send('')
    }))

    route('GET', '/api/admin/events/deliveries', {}, guard('ddrive:ManageEvents', {}, async (req, reply) => {
        const deliveries = await events.listDeliveries({
            status: req.query.status, targetId: req.query.targetId, limit: Math.min(Number(req.query.limit || 100), 1000),
        })

        return json(req, reply, { deliveries })
    }))

    route('POST', '/api/admin/events/redrive', {}, guard('ddrive:RedriveEvents', {}, async (req, reply) => json(req, reply, { requeued: await events.redrive(req.body?.id) })))

    route('GET', '/api/admin/auto-tag-rules', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply) => json(req, reply, { rules: await tagger.listRules() })))
    route('POST', '/api/admin/auto-tag-rules', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply) => json(req, reply, await tagger.createRule(req.body || {}), 201)))
    route('PATCH', '/api/admin/auto-tag-rules/:id', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply, params) => json(req, reply, await tagger.updateRule(params.id, req.body || {}))))
    route('DELETE', '/api/admin/auto-tag-rules/:id', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply, params) => {
        await tagger.deleteRule(params.id)
        reply.code(204)

        return reply.send('')
    }))

    route('POST', '/api/admin/auto-tag-rules/sweep', {}, guard('ddrive:ManageLifecycle', {}, async (req, reply) => json(req, reply, await tagger.sweep({ bucket: req.query.bucket ? await requireBucket(req.query.bucket) : null }))))

    const searchHandler = async (req, reply) => {
        const bucket = req.query.bucket ? await requireBucket(req.query.bucket) : null
        const results = await tagger.searchByTag({
            bucketId: bucket?.id, key: req.query.key, value: req.query.value, limit: Math.min(Number(req.query.limit || 100), 1000),
        })

        return json(req, reply, { objects: results.map((node) => objectJson(bucket, node)) })
    }
    route('GET', '/api/admin/search', {}, guard('s3:ListBucket', {}, searchHandler))
    route('GET', '/api/search', {}, guard('s3:ListBucket', {}, searchHandler))

    route('GET', '/api/admin/settings', {}, guard('ddrive:ReadSettings', {}, async (req, reply) => {
        const rows = await repo.find('setting', {}, { orderBy: [{ column: 'key', dir: 'asc' }] })
        const settings = Object.fromEntries(rows.map((r) => [r.key, r.value]))

        return json(req, reply, {
            settings,
            runtime: {
                version: context.VERSION,
                node: { name: config.node.name, region: config.node.region, defaultBucket: config.node.defaultBucket },
                servers: config.servers,
                workers: config.workers,
                storage: {
                    driver: config.storage.driver, chunkSize: config.storage.chunkSize, tiers: Object.keys(await context.store.health()), encryptAtRest: crypto.enabled,
                },
                security: {
                    publicAccess: config.security.publicAccess,
                    corsOrigins: config.security.corsOrigins,
                    requireHttps: config.security.requireHttps,
                    kms: !!config.security.kmsEndpoint,
                },
                audit: { file: !!config.audit.file, webhook: !!config.audit.webhookUrl, retentionDays: config.audit.retentionDays, events: await repo.count('audit_event') },
                aiTagger: { enabled: !!config.ai.url, heuristic: true },
                encryption: crypto.enabled ? { algorithm: crypto.algorithm, keyId: crypto.keyId, kms: !!config.security.kmsEndpoint } : { enabled: false },
            },
        })
    }))

    route('PUT', '/api/admin/settings/:key', {}, guard('ddrive:WriteSettings', {}, async (req, reply, params, principal) => {
        const { key } = params
        const value = req.body?.value !== undefined ? req.body.value : req.body
        const existing = await repo.findOne('setting', { key })
        if (existing) await repo.update('setting', { key }, { value, updatedBy: principal.name })
        else await repo.insert('setting', {
            key, value, category: req.body?.category || 'general', updatedBy: principal.name,
        })

        return json(req, reply, { key, value })
    }))

    route('GET', '/api/admin/metrics', {}, guard('ddrive:ReadMetrics', {}, async (req, reply) => json(req, reply, { prometheus: metrics.render(), snapshot: metrics.snapshot() })))

    // ==================================================================
    // Presigned URLs helper
    // ==================================================================
    function presignUrl (req, bucketName, key, expiresIn, principal) {
        if (!principal.accessKeyId) {
            throw errors.validation('Presigned URLs require an access key (S3) credential. Create one in the console and sign with it.')
        }
        const accessKey = principal.accessKeyId
        const secret = principal.__secret
        void secret
        throw errors.notImplemented('Presigning is available through the S3 endpoint (/s3) with your access key')
    }
    void sigv4
    void Readable

    // ==================================================================
    // Dispatch
    // ==================================================================
    routes.sort((a, b) => specificity(b) - specificity(a))

    const dispatch = async (req, reply) => {
        const path = req.ddrive?.restPath || req.url.split('?')[0]
        const match = routes.find((r) => matchRoute(r, path, req.method))
        if (!match) {
            reply.code(404)

            return reply.send({ message: 'Not found' })
        }
        const params = matchRoute(match, path, req.method)
        try {
            if (match.options.anon) {
                const principal = await auth.principalFor(req).catch(() => null)
                req.ddrive.principal = principal

                return await match.handler(req, reply, params, principal)
            }
            const principal = await auth.requirePrincipal(req, reply)
            req.ddrive.principal = principal
            const resource = match.options.resource ? await match.options.resource(req, params) : {}
            if (match.options.action) await auth.authorize(req, principal, match.options.action, resource)

            return await match.handler(req, reply, params, principal)
        } catch (err) {
            if (!err.statusCode) err.statusCode = 500
            if (err.statusCode >= 500) logger.error?.({ err, url: req.url }, 'rest request failed')
            const statusCode = err.statusCode
            reply.code(statusCode)
            reply.header('content-type', 'application/json; charset=utf-8')

            return reply.send({
                message: err.expose === false || statusCode >= 500 ? 'Internal server error' : err.message,
                code: err.code,
            })
        }
    }

    return { dispatch, routes, objectJson, bucketJson }
}

module.exports = { createRestServer }
