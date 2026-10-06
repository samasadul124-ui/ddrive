/**
 * WebDAV server (RFC 4918) for DDrive.
 *
 * Mounting `/webdav/` exposes every bucket as a top level collection, so a
 * plain `mount -t davfs https://host/webdav/ /mnt/ddrive` gives you the whole
 * storage system with Windows Explorer, macOS Finder, davfs2, rclone, cadaver,
 * gvfs, ...
 *
 * Implemented: PROPFIND (Depth 0/1/infinity, allprop/propname/specific props),
 * PROPPATCH (dead properties persist in object metadata), MKCOL, GET/HEAD with
 * Range, PUT, DELETE (recursive, respects Depth), COPY/MOVE (Overwrite +
 * Destination), LOCK/UNLOCK (exclusive and shared write locks with timeouts and
 * If-header token validation) and OPTIONS with DAV: 1, 2, 3.
 */
const { randomUUID } = require('crypto')
const util = require('../../lib/util')
const xml = require('../../lib/xml')
const { errors, StorageError } = require('../../lib/errors')

const DEFAULT_MAX_DEPTH = 32
const DEFAULT_LOCK_TIMEOUT = 3600
const MAX_LOCK_TIMEOUT = 7 * 86400
const ALLOWED_METHODS = 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK'
const DAV_CLASSES = '1, 2, 3'
const NS_DAV = 'DAV:'
const NS_DDRIVE = 'urn:ddrive:webdav'

const createWebdavServer = (context, deps) => {
    const {
        objects, buckets, repo, audit, config,
    } = context
    const { auth } = deps
    const maxDepth = config.servers?.webdav?.maxDepth || DEFAULT_MAX_DEPTH
    const autoMkcol = config.servers?.webdav?.autoMkcol !== false

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    /** Strip the WebDAV mount prefix from an absolute or relative path. */
    const stripMount = (path) => {
        const mount = MOUNT
        if (path === mount) return '/'
        if (mount !== '/' && path.startsWith(`${mount}/`)) return path.slice(mount.length)
        if (path.startsWith('/webdav/')) return path.slice('/webdav'.length)

        return path
    }

    const parseTarget = (rawPath, url) => {
        let path = util.normalizePath(util.decodeURIComponentSafe(rawPath || '/'))
        let host = null
        if (typeof rawPath === 'string' && rawPath.includes('://')) {
            const parsed = new URL(rawPath)
            path = util.normalizePath(util.decodeURIComponentSafe(parsed.pathname))
            host = parsed.host
        } else if (url && url.includes('://')) {
            const parsed = new URL(url)
            path = util.normalizePath(util.decodeURIComponentSafe(parsed.pathname))
            host = parsed.host
        }
        path = util.normalizePath(stripMount(path))
        const parts = path.split('/').filter(Boolean)

        return {
            parts, host, bucketName: parts.length ? parts[0] : null, key: parts.slice(1).join('/'),
        }
    }

    const resolveNode = async (bucketName, key) => {
        if (!bucketName) return { root: true }
        const bucket = await buckets.get(bucketName)
        if (!key) return { bucket, node: null, isBucketRoot: true }
        const node = await objects.getNode(bucket.id, key)

        return { bucket, node, isBucketRoot: false }
    }

    const MOUNT = `/${(config.servers.webdav.path || '/webdav').replace(/^\/+|\/+$/g, '')}`
    const href = (bucketName, key) => {
        const encoded = key ? String(key).split('/').map((part) => encodeURIComponent(part)).join('/') : ''
        const segments = [bucketName, encoded].filter((s) => s !== undefined && s !== '')
        if (!segments.length) return `${MOUNT}/`

        return `${MOUNT}/${segments.join('/')}`
    }
    const writeRequiresNoLock = async (bucket, key, ifHeader, principal) => {
        const token = parseIfHeader(ifHeader)
        if (token === true) return true
        const rows = await repo.find('webdav_lock', { bucketId: bucket.id, expiresAt: { gt: new Date() } })
        const normalized = util.normalizeKey(key)
        const relevant = rows.filter((lock) => (lock.depth === 'infinity'
            ? (normalized === lock.path || normalized.startsWith(`${lock.path}/`))
            : normalized === lock.path))
        if (!relevant.length) return true
        if (relevant.every((lock) => lock.scope === 'shared' && lock.principalId === principal?.id)) return true
        if (token && relevant.some((lock) => lock.token === token)) return true

        throw new StorageError('Locked', 'The resource is locked by another client', { statusCode: 423 })
    }

    /** `If` header parsing: <token> or (<token>) / (Not <token>) lists. */
    const parseIfHeader = (header) => {
        if (!header) return null
        const text = String(header)
        const tokens = [...text.matchAll(/<([^>]+)>/g)].map((m) => m[1])
        // "Not <token>" means the client asserts absence; treat as no token
        if (/\(\s*not\s+/i.test(text)) return null
        const lockToken = tokens.map((t) => t.replace(/^opaquelocktoken:/i, '')).find((t) => t)

        return lockToken || null
    }

    const parseTimeout = (header) => {
        if (!header) return DEFAULT_LOCK_TIMEOUT
        const match = /(Second-)?(\d+)/i.exec(String(header))
        if (!match) return DEFAULT_LOCK_TIMEOUT

        return Math.min(Number(match[2]), MAX_LOCK_TIMEOUT)
    }

    const lockDiscovery = (lock) => ({
        'D:activelock': {
            'D:locktype': { 'D:write': {} },
            'D:lockscope': lock.scope === 'shared' ? { 'D:shared': {} } : { 'D:exclusive': {} },
            'D:depth': lock.depth,
            'D:owner': lock.ownerXml ? { '#text': lock.ownerXml } : {},
            'D:timeout': `Second-${Math.max(0, Math.round((new Date(lock.expiresAt).getTime() - Date.now()) / 1000))}`,
            'D:locktoken': { 'D:href': `opaquelocktoken:${lock.token}` },
            'D:lockroot': { 'D:href': lock.href || '/' },
        },
    })

    const existingLock = async (bucket, key) => {
        const rows = await repo.find('webdav_lock', {
            bucketId: bucket.id, path: util.normalizeKey(key), expiresAt: { gt: new Date() },
        })
        if (!rows.length) return null

        return { ...rows[0], href: href(bucket.name, key) }
    }

    const propertyResponse = async (bucket, node, props, { nameOnly = false, allProp = false } = {}) => {
        const isCollection = !node || node.type === 'directory'
        const key = node ? node.path : ''
        const prop = {}
        const missing = []
        const wanted = props.length ? props : []

        const live = {
            resourcetype: isCollection ? { 'D:collection': {} } : '',
            getlastmodified: util.httpDate(node?.updatedAt || node?.createdAt || new Date()),
            creationdate: util.iso(node?.createdAt || new Date()),
            displayname: node ? node.name : bucket.name,
            supportedlock: {
                'D:lockentry': [
                    { 'D:lockscope': { 'D:exclusive': {} }, 'D:locktype': { 'D:write': {} } },
                    { 'D:lockscope': { 'D:shared': {} }, 'D:locktype': { 'D:write': {} } },
                ],
            },
        }
        if (!isCollection) {
            live.getcontentlength = String(Number(node.size || 0))
            live.getcontenttype = node.contentType || util.contentTypeOf(node.name)
            live.getetag = node.etag || ''
        }

        const extras = {
            'D:lockdiscovery': await (async () => {
                if (isCollection) return {}
                const lock = node ? await existingLock(bucket, node.path) : null

                return lock ? lockDiscovery(lock) : {}
            })(),
            'D:quota-available-bytes': '-1',
            'D:quota-used-bytes': String(Number(await repo.aggregate('directory', 'sum', 'size', { bucketId: bucket.id, type: 'file', deletedAt: null }) || 0)),
            'ddrive:storage-class': node?.storageClass || 'STANDARD',
            'ddrive:version-id': node?.latestVersionId || '',
            'ddrive:encrypted': node?.metadata && node.metadata.encrypted ? 'true' : (node ? 'true' : ''),
            'ddrive:path': key,
        }

        const known = { ...live, ...extras }
        if (allProp) {
            Object.entries(known).forEach(([k, v]) => { if (!nameOnly) prop[k] = v })

            return { prop, missing: [] }
        }
        if (!wanted.length) {
            // allprop with no body
            Object.entries(known).forEach(([k, v]) => { if (!nameOnly) prop[k] = v })

            return { prop, missing: [] }
        }
        for (const requested of wanted) {
            const bare = requested.split(':').pop()
            if (known[requested] !== undefined || known[`D:${bare}`] !== undefined || known[`ddrive:${bare}`] !== undefined) {
                const value = known[requested] !== undefined ? known[requested] : (known[`D:${bare}`] !== undefined ? known[`D:${bare}`] : known[`ddrive:${bare}`])
                if (!nameOnly) prop[requested] = value
            } else if (node?.metadata?.['webdav:props']?.[requested] !== undefined) {
                if (!nameOnly) prop[requested] = node.metadata['webdav:props'][requested]
            } else {
                missing.push(requested)
            }
        }

        return { prop, missing }
    }

    const responseXml = async (bucket, node, props, opts) => {
        const { prop, missing } = await propertyResponse(bucket, node, props, opts)
        const statuses = []
        if (Object.keys(prop).length || !missing.length) {
            statuses.push({ 'D:propstat': { 'D:prop': prop, 'D:status': 'HTTP/1.1 200 OK' } })
        }
        if (missing.length) {
            const missingProp = {}
            missing.forEach((name) => { missingProp[name] = {} })
            statuses.push({ 'D:propstat': { 'D:prop': missingProp, 'D:status': 'HTTP/1.1 404 Not Found' } })
        }
        const key = node ? node.path : ''
        const isCollection = !node || node.type === 'directory'

        return {
            'D:href': href(bucket.name, key),
            ...(isCollection ? { 'D:resourcetype': {} } : {}),
            ...statuses.reduce((acc, status) => ({ ...acc, ...status }), {}),
        }
    }

    const send = (reply, statusCode, body) => {
        reply.code(statusCode).header('content-type', 'application/xml; charset=utf-8')

        return reply.send(body)
    }

    const multistatus = (responses) => {
        const payload = { 'D:multistatus': { '@_xmlns:D': NS_DAV, '@_xmlns:ddrive': NS_DDRIVE } }
        const list = responses.length === 1 ? responses[0] : responses
        payload['D:multistatus']['D:response'] = list
        if (!Array.isArray(list)) payload['D:multistatus']['D:response'] = [list]

        return xml.buildXml(payload)
    }

    // ------------------------------------------------------------------
    // Handlers
    // ------------------------------------------------------------------
    const options = async (req, reply) => {
        reply.header('dav', DAV_CLASSES)
        reply.header('allow', ALLOWED_METHODS)
        reply.header('ms-author-via', 'DAV')
        reply.header('accept-ranges', 'bytes')
        reply.code(200)

        return reply.send('')
    }

    const getOrHead = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName) {
            // root: render a tiny HTML index of the buckets for Browsers
            await auth.authorize(req, principal, 'webdav:ListBuckets', {})
            const list = await buckets.list()
            reply.header('content-type', 'text/html; charset=utf-8')

            return reply.send(`<!doctype html><html><body><h1>DDrive</h1><ul>${list.map((b) => `<li><a href="${href(b.name)}/">${util.escapeXml(b.name)}</a></li>`).join('')}</ul></body></html>`)
        }
        const { bucket, node, isBucketRoot } = await resolveNode(bucketName, key)
        await auth.authorize(req, principal, 'webdav:Read', { bucket: bucketName, key })
        if (!isBucketRoot && (!node || node.type === 'directory')) {
            if (!node) throw errors.noSuchKey(key)
            const children = await objects.children(bucket, key)
            reply.header('content-type', 'text/html; charset=utf-8')
            const rows = children.filter((c) => !c.deletedAt).map((child) => {
                const name = child.type === 'directory' ? `${child.name}/` : child.name

                return `<li><a href="${href(bucketName, child.path)}">${util.escapeXml(name)}</a></li>`
            }).join('')

            return reply.send(`<!doctype html><html><body><h1>/${util.escapeXml(`${bucketName}/${key}`)}</h1><ul>${rows}</ul></body></html>`)
        }
        if (isBucketRoot) {
            const children = await objects.children(bucket, '')
            reply.header('content-type', 'text/html; charset=utf-8')

            return reply.send(`<!doctype html><html><body><h1>${util.escapeXml(bucketName)}</h1><ul>${children.map((c) => `<li><a href="${href(bucketName, c.path)}">${util.escapeXml(c.name)}</a></li>`).join('')}</ul></body></html>`)
        }
        const version = await repo.findOne('object_version', { id: node.latestVersionId })
        const range = req.headers.range ? util.parseRange(req.headers.range, Number(version.size)) : null
        const result = await objects.stream(version, range)
        reply.code(range ? 206 : 200)
        reply.header('content-type', version.contentType || util.contentTypeOf(node.name))
        reply.header('etag', `"${node.etag}"`)
        reply.header('last-modified', util.httpDate(node.updatedAt || node.createdAt))
        reply.header('accept-ranges', 'bytes')
        reply.header('content-length', String(range ? range.length : version.size))
        if (range) reply.header('content-range', `bytes ${range.start}-${range.end}/${version.size}`)
        await objects.recordAccess(version, range ? range.length : version.size)

        return reply.send(req.method === 'HEAD' ? '' : result.stream)
    }

    const findProps = (body) => {
        const parsed = xml.parseXml(body)
        const propfind = xml.node(parsed, 'propfind') || {}
        const propNode = xml.node(propfind, 'prop')
        const props = propNode && typeof propNode === 'object'
            ? Object.keys(propNode).filter((k) => !k.startsWith('@_'))
            : []
        const allProp = xml.node(propfind, 'allprop') !== undefined && !props.length
        const nameOnly = xml.node(propfind, 'propname') !== undefined

        return { props, allProp, nameOnly }
    }

    const walkDepth = async (bucket, node, depth, out, current = 0) => {
        out.push(node)
        if (depth !== 'infinity' && current >= depth) return
        if (current + 1 > maxDepth) return
        const children = node === null ? await objects.children(bucket, '') : await objects.children(bucket, node.path)
        for (const child of children.filter((c) => !c.deletedAt)) {
            // eslint-disable-next-line no-await-in-loop
            await walkDepth(bucket, child, depth, out, current + 1)
        }
    }

    const propfind = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        const body = await util.bodyText(req)
        const { props, allProp, nameOnly } = findProps(body)
        const depthHeader = String(req.headers.depth === undefined ? '1' : req.headers.depth).toLowerCase()
        const depth = depthHeader === 'infinity' ? 'infinity' : (depthHeader === '0' ? 0 : 1)
        if (!bucketName) {
            await auth.authorize(req, principal, 'webdav:ListBuckets', {})
            const list = await buckets.list()
            const responses = []
            for (const bucket of list) {
                const { prop, missing } = await propertyResponse(bucket, null, props, { nameOnly, allProp })
                void missing
                responses.push({
                    'D:href': href(bucket.name),
                    'D:propstat': { 'D:prop': prop, 'D:status': 'HTTP/1.1 200 OK' },
                })
            }

            return send(reply, 207, multistatus(responses))
        }
        const { bucket, node, isBucketRoot } = await resolveNode(bucketName, key)
        await auth.authorize(req, principal, 'webdav:Read', { bucket: bucketName, key })
        if (!isBucketRoot && !node) throw errors.noSuchKey(key)
        if (isBucketRoot) {
            const children = (await objects.children(bucket, '')).filter((c) => !c.deletedAt)
            const responses = [await responseXml(bucket, null, props, { nameOnly, allProp })]
            if (depth !== 0) {
                for (const child of children) {
                    // eslint-disable-next-line no-await-in-loop
                    responses.push(await responseXml(bucket, child, props, { nameOnly, allProp }))
                }
            }

            return send(reply, 207, multistatus(responses))
        }
        const collected = []
        await walkDepth(bucket, node, depth, collected)
        const responses = []
        for (const item of collected) {
            // eslint-disable-next-line no-await-in-loop
            responses.push(await responseXml(bucket, item, props, { nameOnly, allProp }))
        }

        return send(reply, 207, multistatus(responses))
    }

    const proppatch = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName || !key) throw errors.methodNotAllowed('PROPPATCH requires a collection or object')
        const { bucket, node } = await resolveNode(bucketName, key)
        await auth.authorize(req, principal, 'webdav:Write', { bucket: bucketName, key })
        if (!node) throw errors.noSuchKey(key)
        await writeRequiresNoLock(bucket, key, req.headers.if, principal)
        const parsed = xml.parseXml(await util.bodyText(req))
        const root = xml.node(parsed, 'propertyupdate') || {}
        const props = { ...(node.metadata?.['webdav:props'] || {}) }
        const results = {}
        for (const action of ['set', 'remove']) {
            const container = xml.node(root, action)
            if (!container) continue
            const propNode = xml.node(container, 'prop') || {}
            for (const [name, value] of Object.entries(propNode)) {
                if (name.startsWith('@_')) continue
                if (action === 'set') props[name] = typeof value === 'object' ? (xml.text(value) ?? '') : String(value ?? '')
                else delete props[name]
                results[name] = action === 'set' ? 200 : 200
            }
        }
        const metadata = { ...(node.metadata || {}), 'webdav:props': props }
        await objects.updateObject(bucket, key, { metadata }, { id: principal?.id, name: principal?.name, protocol: 'webdav' })
        const propstats = {
            'D:propstat': {
                'D:prop': Object.fromEntries(Object.keys(results).map((name) => [name, {}])),
                'D:status': 'HTTP/1.1 200 OK',
            },
        }

        return send(reply, 207, multistatus([{ 'D:href': href(bucketName, key), ...propstats }]))
    }

    const mkcol = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName) throw errors.methodNotAllowed('Cannot create the DDrive root collection')
        if (!key) throw new StorageError('MethodNotAllowed', 'The bucket already exists', { statusCode: 405 })
        const bucket = await buckets.get(bucketName)
        await auth.authorize(req, principal, 'webdav:Write', { bucket: bucketName, key })
        const existing = await objects.getNode(bucket.id, key)
        if (existing) throw new StorageError('MethodNotAllowed', 'The collection already exists', { statusCode: 405 })
        await objects.createDirectory(bucket, key, { actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' } })
        reply.code(201)

        return reply.send('')
    }

    const put = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName || !key) throw errors.methodNotAllowed('PUT requires a bucket and an object path')
        const bucket = await buckets.get(bucketName)
        await auth.authorize(req, principal, 'webdav:Write', { bucket: bucketName, key })
        await writeRequiresNoLock(bucket, key, req.headers.if, principal)
        if (autoMkcol && key.includes('/')) await objects.ensurePath(bucket, key, { actor: { id: principal?.id, name: principal?.name } })
        const existing = await objects.getNode(bucket.id, key)
        const conditions = {
            ifNoneMatch: req.headers['if-none-match'],
            ifMatch: req.headers['if-match'],
        }
        if (existing && req.headers['if-none-match'] === '*') throw errors.preconditionFailed()
        const result = await objects.putObject({
            bucket,
            path: key,
            stream: util.bodyStream(req),
            contentType: req.headers['content-type'] || util.contentTypeOf(key),
            actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' },
            conditions,
        })
        reply.header('etag', `"${result.etag}"`)
        reply.code(existing ? 204 : 201)
        await audit.record({
            action: 'webdav.Put', actor: principal?.name, actorId: principal?.id, bucket: bucketName, objectKey: key, protocol: 'webdav', ip: req.ddrive.ip, requestId: req.id, detail: { bytes: result.size, created: !existing }, result: 'success',
        })

        return reply.send('')
    }

    const remove = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName) throw errors.methodNotAllowed('Cannot delete the DDrive root collection')
        const { bucket, node, isBucketRoot } = await resolveNode(bucketName, key)
        await auth.authorize(req, principal, 'webdav:Write', { bucket: bucketName, key })
        if (isBucketRoot) {
            if (req.headers.depth !== 'infinity') throw new StorageError('Conflict', 'Depth: infinity is required to delete a collection', { statusCode: 409 })
            await buckets.remove(bucketName, { force: true, actor: principal?.name })
            reply.code(204)

            return reply.send('')
        }
        if (!node) throw errors.noSuchKey(key)
        await writeRequiresNoLock(bucket, key, req.headers.if, principal)
        if (node.type === 'directory') {
            const children = (await objects.children(bucket, key)).filter((c) => !c.deletedAt)
            if (children.length && req.headers.depth !== 'infinity') {
                throw new StorageError('Conflict', 'Depth: infinity is required to delete a non-empty collection', { statusCode: 409 })
            }
            await objects.deleteDirectory(bucket, key, {
                recursive: true, permanent: true, actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' },
            })
        } else {
            await objects.deleteObject({
                bucket, path: key, permanent: true, actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' },
            })
        }
        await repo.delete('webdav_lock', { bucketId: bucket.id, path: util.normalizeKey(key) })
        await audit.record({
            action: 'webdav.Delete', actor: principal?.name, actorId: principal?.id, bucket: bucketName, objectKey: key, protocol: 'webdav', ip: req.ddrive.ip, requestId: req.id, result: 'success',
        })
        reply.code(204)

        return reply.send('')
    }

    const copyOrMove = async (req, reply, isMove) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        const destination = req.headers.destination
        if (!destination) throw errors.invalidArgument('The Destination header is required')
        const target = parseTarget(destination)
        if (target.host && req.headers.host && target.host !== req.headers.host) {
            throw new StorageError('BadGateway', 'The destination is on a different server', { statusCode: 502 })
        }
        if (!bucketName || !key || !target.bucketName) throw errors.invalidArgument('Invalid source or destination')
        const source = await resolveNode(bucketName, key)
        if (!source.node) throw errors.noSuchKey(key)
        const destinationBucket = await buckets.get(target.bucketName)
        await auth.authorize(req, principal, 'webdav:Read', { bucket: bucketName, key })
        await auth.authorize(req, principal, 'webdav:Write', { bucket: target.bucketName, key: target.key })
        if (isMove) await writeRequiresNoLock(source.bucket, key, req.headers.if, principal)
        await writeRequiresNoLock(destinationBucket, target.key, req.headers.if, principal)
        const existing = await objects.getNode(destinationBucket.id, target.key)
        const overwrite = String(req.headers.overwrite || 'T').toUpperCase() !== 'F'
        if (existing && !overwrite) throw errors.preconditionFailed('The destination resource already exists and Overwrite is F')
        if (existing) {
            if (existing.type === 'directory') await objects.deleteDirectory(destinationBucket, target.key, { actor: { id: principal?.id, name: principal?.name } })
            else {
                await objects.deleteObject({
                    bucket: destinationBucket, path: target.key, permanent: true, actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' },
                })
            }
        }
        if (source.node.type === 'directory') {
            await objects.copy(
                { bucket: source.bucket, path: key },
                { bucket: destinationBucket, path: target.key },
                { recursive: true, actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' } },
            )
            if (isMove) await objects.deleteDirectory(source.bucket, key, { actor: { id: principal?.id, name: principal?.name } })
        } else if (isMove) {
            await objects.move(source.bucket, key, target.key, { actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' } })
        } else {
            await objects.copy(
                { bucket: source.bucket, path: key },
                { bucket: destinationBucket, path: target.key },
                { actor: { id: principal?.id, name: principal?.name, protocol: 'webdav' } },
            )
        }
        await audit.record({
            action: isMove ? 'webdav.Move' : 'webdav.Copy', actor: principal?.name, actorId: principal?.id, bucket: bucketName, objectKey: key, protocol: 'webdav', detail: { destination: target.key }, ip: req.ddrive.ip, requestId: req.id, result: 'success',
        })
        reply.code(existing ? 204 : 201)

        return reply.send('')
    }

    const lock = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName) throw errors.methodNotAllowed('Cannot lock the DDrive root collection')
        const { bucket, node, isBucketRoot } = await resolveNode(bucketName, key)
        await auth.authorize(req, principal, 'webdav:Write', { bucket: bucketName, key })
        if (!isBucketRoot && !node && req.headers['content-length'] !== '0') throw errors.noSuchKey(key)
        const body = (await util.bodyText(req)).trim()
        const ifToken = parseIfHeader(req.headers.if)
        const refreshToken = ifToken && !body ? ifToken : null
        if (refreshToken) {
            const existing = await repo.findOne('webdav_lock', { token: refreshToken })
            if (!existing) throw new StorageError('PreconditionFailed', 'The lock token is not valid', { statusCode: 412 })
            const timeoutSeconds = parseTimeout(req.headers.timeout)
            await repo.update('webdav_lock', { id: existing.id }, {
                expiresAt: util.addSeconds(new Date(), timeoutSeconds), timeoutSeconds,
            })
            const lockRow = { ...existing, expiresAt: util.addSeconds(new Date(), timeoutSeconds), href: href(bucketName, key) }
            reply.header('lock-token', `<opaquelocktoken:${existing.token}>`)
            reply.code(200)

            return send(reply, 200, xml.buildXml({ 'D:prop': { '@_xmlns:D': NS_DAV, ...lockDiscovery(lockRow) } }))
        }
        const parsed = xml.parseXml(body)
        const lockinfo = xml.node(parsed, 'lockinfo') || {}
        const scopeNode = xml.node(lockinfo, 'lockscope') || {}
        const isShared = xml.node(scopeNode, 'shared') !== undefined
        const ownerNode = xml.node(lockinfo, 'owner')
        const owner = ownerNode ? (xml.text(ownerNode) || xml.buildXml({ owner: ownerNode }).replace(/<\?xml[^>]*\?>\s*/, '')) : null
        const depth = String(req.headers.depth || 'infinity') === '0' ? '0' : 'infinity'
        const timeoutSeconds = parseTimeout(req.headers.timeout)
        const token = randomUUID().replace(/-/g, '')
        const expiresAt = util.addSeconds(new Date(), timeoutSeconds)
        // shared locks may coexist, an exclusive lock conflicts with everything
        const conflicts = await repo.find('webdav_lock', { bucketId: bucket.id, expiresAt: { gt: new Date() } })
        const normalized = util.normalizeKey(key)
        const conflicting = conflicts.filter((existing) => {
            const overlaps = existing.path === normalized
                || (existing.depth === 'infinity' && normalized.startsWith(`${existing.path}/`))
                || (depth === 'infinity' && existing.path.startsWith(`${normalized}/`))
            if (!overlaps) return false
            if (!isShared || existing.scope === 'exclusive') return true

            return false
        })
        if (conflicting.length) throw new StorageError('Locked', 'The resource is already locked', { statusCode: 423 })
        await repo.insert('webdav_lock', {
            bucketId: bucket.id,
            path: normalized,
            token,
            principalId: principal?.id || null,
            ownerXml: owner ? String(owner).slice(0, 512) : null,
            scope: isShared ? 'shared' : 'exclusive',
            type: 'write',
            depth,
            timeoutSeconds,
            root: true,
            expiresAt,
        })
        const lockRow = {
            token, scope: isShared ? 'shared' : 'exclusive', depth, ownerXml: owner ? String(owner).slice(0, 512) : null, expiresAt, href: href(bucketName, key),
        }
        reply.header('lock-token', `<opaquelocktoken:${token}>`)
        reply.code(200)
        await audit.record({
            action: 'webdav.Lock', actor: principal?.name, actorId: principal?.id, bucket: bucketName, objectKey: key, protocol: 'webdav', detail: { scope: lockRow.scope, depth, timeoutSeconds }, ip: req.ddrive.ip, requestId: req.id, result: 'success',
        })

        return send(reply, 200, xml.buildXml({ 'D:prop': { '@_xmlns:D': NS_DAV, ...lockDiscovery(lockRow) } }))
    }

    const unlock = async (req, reply) => {
        const { bucketName, key } = parseTarget(req.ddrive.davPath)
        const principal = req.ddrive.principal
        if (!bucketName) throw errors.methodNotAllowed('Cannot unlock the DDrive root collection')
        const token = parseIfHeader(req.headers['lock-token'] || req.headers.if)
        if (!token) throw errors.invalidArgument('A Lock-Token header is required')
        const lock = await repo.findOne('webdav_lock', { token })
        if (!lock) throw new StorageError('Conflict', 'The lock token is not valid', { statusCode: 409 })
        await auth.authorize(req, principal, 'webdav:Write', { bucket: bucketName, key })
        await repo.delete('webdav_lock', { id: lock.id })
        reply.code(204)

        return reply.send('')
    }

    const handlers = {
        OPTIONS: options,
        PROPFIND: propfind,
        PROPPATCH: proppatch,
        MKCOL: mkcol,
        GET: getOrHead,
        HEAD: getOrHead,
        PUT: put,
        DELETE: remove,
        COPY: (req, reply) => copyOrMove(req, reply, false),
        MOVE: (req, reply) => copyOrMove(req, reply, true),
        LOCK: lock,
        UNLOCK: unlock,
    }

    const dispatch = async (req, reply) => {
        const handler = handlers[req.method]
        if (!handler) {
            reply.header('allow', ALLOWED_METHODS)
            reply.code(405)

            return reply.send('')
        }
        const principal = await auth.requirePrincipal(req, reply)
        req.ddrive.principal = principal

        return handler(req, reply)
    }

    return { dispatch, handlers, ALLOWED_METHODS, DAV_CLASSES }
}

module.exports = { createWebdavServer }
