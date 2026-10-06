/**
 * HTTP entrypoint: one Fastify listener exposing every DDrive surface.
 *
 *   /            legacy DDrive panel (unchanged, talks to the /api routes below)
 *   /console/    new operator console (SPA, session cookies / bearer tokens)
 *   /api/        REST API (v4 compatible panel routes + v5 bucket/object + admin)
 *   /webdav/     WebDAV (class 1, 2 and 3): mount it as a network drive
 *   /s3/         S3 compatible API (path and virtual host style, SigV4)
 *   /share/:tok  public share links
 *   /metrics /healthz /readyz      operational endpoints
 *   /_internal/  node to node replication API (HMAC signed)
 *
 * Content type handling: JSON / form bodies are parsed, XML and everything
 * else arrives as an unread stream so uploads never buffer in memory. Servers
 * read `req.body` when it is a stream, or fall back to `req.raw`.
 */
const path = require('path')
const querystring = require('querystring')
const Fastify = require('fastify')
const FastifyStatic = require('@fastify/static')
const FastifyMultipart = require('@fastify/multipart')

const { createContext, VERSION } = require('../core/context')
const { createAuth } = require('../servers/auth')
const { createS3Server } = require('../servers/s3')
const { createWebdavServer } = require('../servers/webdav')
const { createRestServer } = require('../servers/rest')
const { registerMonitoring } = require('../servers/monitoring')
const util = require('../lib/util')

const PANEL_DIR = path.join(__dirname, 'html')
const CONSOLE_DIR = path.join(__dirname, '..', 'servers', 'console')

const DAV_METHODS = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
const S3_METHODS = ['GET', 'HEAD', 'PUT', 'POST', 'DELETE', 'OPTIONS']
const REST_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

const trimSlash = (value, fallback) => {
    const pathValue = (value || fallback || '').trim()
    if (!pathValue || pathValue === '/') return ''
    const withSlash = pathValue.startsWith('/') ? pathValue : `/${pathValue}`

    return withSlash.replace(/\/+$/, '')
}

const decodeSegments = (value) => String(value || '')
    .split('/')
    .map((segment) => util.decodeURIComponentSafe(segment))
    .join('/')

const createHttpServer = (config, opts = {}) => {
    const fastify = Fastify({
        logger: opts.logger === false ? false : {
            level: config.logLevel || 'info',
            base: undefined,
        },
        trustProxy: config.security.trustProxy,
        bodyLimit: config.servers.bodyLimit,
        disableRequestLogging: config.logLevel !== 'debug' && config.logLevel !== 'trace',
        ignoreTrailingSlash: false,
        connectionTimeout: 0,
        keepAliveTimeout: 72000,
    })

    const context = opts.context || createContext(config, { logger: fastify.log })
    const sharePublicAccess = config.security.allowPublicShare !== false

    const auth = createAuth(context)
    const s3Server = createS3Server(context, { auth })
    const webdavServer = createWebdavServer(context, { auth })
    const restServer = createRestServer(context, { auth })

    const webdavPath = trimSlash(config.servers.webdav.path, '/webdav') || '/webdav'
    const s3Path = trimSlash(config.servers.s3.path, '/s3') || '/s3'

    // ------------------------------------------------------------------
    // Content types
    // ------------------------------------------------------------------
    fastify.removeAllContentTypeParsers()
    fastify.addContentTypeParser(['application/json', 'application/*+json'], { parseAs: 'string' }, (req, body, done) => {
        if (!body) return done(null, undefined)
        try {
            return done(null, JSON.parse(body))
        } catch (err) {
            err.statusCode = 400
            err.code = 'InvalidRequest'

            return done(err)
        }
    })
    fastify.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (req, body, done) => {
        done(null, body ? querystring.parse(body) : {})
    })
    // everything else (xml, octet-stream, ...) stays a readable stream: uploads
    // are streamed straight into the chunk store without buffering.
    fastify.addContentTypeParser('*', { bodyLimit: Infinity }, (req, payload, done) => done(null, payload))

    fastify.register(FastifyMultipart, {
        limits: { fileSize: Infinity, files: 10, fields: 100 },
        attachFieldsToBody: false,
    })

    // ------------------------------------------------------------------
    // Request decoration
    // ------------------------------------------------------------------
    fastify.decorateRequest('ddrive', null)
    fastify.addHook('onRequest', async (req, reply) => {
        const rawUrl = req.raw.url || '/'
        const qIndex = rawUrl.indexOf('?')
        const rawPath = qIndex === -1 ? rawUrl : rawUrl.slice(0, qIndex)
        const decoded = decodeSegments(rawPath)
        const ddrive = {
            startedAt: Date.now(),
            ip: req.ip,
            secure: req.protocol === 'https',
            rawUrl,
            rawPath,
            rawQuery: qIndex === -1 ? '' : rawUrl.slice(qIndex + 1),
            path: decoded,
            protocol: 'rest',
            mount: '',
            shareToken: null,
            principal: null,
            bucket: null,
        }
        const suffix = (mount) => {
            const rest = decoded.slice(mount.length)
            const rawRest = rawPath.slice(mount.length)

            return { rest: rest || '/', rawRest: rawRest || '/' }
        }
        if (webdavPath && (decoded === webdavPath || decoded.startsWith(`${webdavPath}/`))) {
            ddrive.protocol = 'webdav'
            ddrive.mount = webdavPath
            const { rawRest } = suffix(webdavPath)
            ddrive.davPath = rawRest
            ddrive.s3Path = rawRest
            ddrive.restPath = decoded
        } else if (s3Path && (decoded === s3Path || decoded.startsWith(`${s3Path}/`))) {
            ddrive.protocol = 's3'
            ddrive.mount = s3Path
            ddrive.s3Prefix = s3Path
            const { rawRest: s3Rest } = suffix(s3Path)
            ddrive.s3Path = s3Rest
            ddrive.davPath = s3Rest
            ddrive.restPath = decoded
        } else if (decoded === '/console' || decoded.startsWith('/console/')) {
            ddrive.protocol = 'console'
            ddrive.restPath = decoded
        } else {
            ddrive.restPath = decoded
        }
        req.ddrive = ddrive

        // CORS: S3/WebDAV/REST clients running in a browser
        const origin = req.headers.origin
        if (origin) {
            const allowed = config.security.corsOrigins.length
                ? config.security.corsOrigins.includes(origin) || config.security.corsOrigins.includes('*')
                : true
            if (allowed) {
                reply.header('access-control-allow-origin', origin)
                reply.header('access-control-allow-credentials', 'true')
                reply.header('vary', 'Origin')
                if (req.method === 'OPTIONS' && req.headers['access-control-request-method']) {
                    reply.header('access-control-allow-methods', 'GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK')
                    reply.header('access-control-allow-headers', req.headers['access-control-request-headers'] || '*')
                    reply.header('access-control-expose-headers', 'ETag, x-amz-request-id, x-amz-version-id, x-ddrive-version-id')
                    reply.header('access-control-max-age', '600')
                    reply.code(204)

                    return reply.send('')
                }
            }
        }

        return undefined
    })

    // Requests that never touch their body would keep the socket half open.
    fastify.addHook('onResponse', async (req) => {
        const body = req.body
        if (body && typeof body.pipe === 'function' && !body.destroyed && typeof body.resume === 'function') {
            body.resume()
        }
    })

    if (config.security.requireHttps) {
        fastify.addHook('onRequest', async (req) => {
            if (!req.ddrive.secure && req.headers['x-forwarded-proto'] !== 'https') {
                const { errors } = require('../lib/errors')
                throw errors.invalidRequest('HTTPS is required')
            }
        })
    }

    void context.metrics.fastifyPlugin(fastify)

    // ------------------------------------------------------------------
    // Routes
    // ------------------------------------------------------------------
    if (config.servers.webdav.enabled !== false) {
        const handler = (req, reply) => webdavServer.dispatch(req, reply)
        fastify.route({ method: DAV_METHODS, url: webdavPath, handler })
        fastify.route({ method: DAV_METHODS, url: `${webdavPath}/*`, handler })
    }

    if (config.servers.s3.enabled !== false) {
        const handler = (req, reply) => s3Server.dispatch(req, reply)
        fastify.route({ method: S3_METHODS, url: s3Path, handler })
        fastify.route({ method: S3_METHODS, url: `${s3Path}/*`, handler })
        if (config.servers.s3.virtualHost) {
            fastify.addHook('onRequest', async (req, reply) => {
                const host = String(req.headers.host || '')
                if (req.ddrive.protocol === 's3') return
                if (host.endsWith(config.servers.s3.virtualHost)) {
                    req.ddrive.protocol = 's3'
                    req.ddrive.s3Prefix = ''
                    req.ddrive.s3Path = req.ddrive.rawPath
                    req.ddrive.bucket = host.slice(0, -config.servers.s3.virtualHost.length).replace(/\.$/, '')
                }
                return undefined
            })
        }
    }

    const apiHandler = (req, reply) => restServer.dispatch(req, reply)
    fastify.route({ method: REST_METHODS, url: '/api', handler: apiHandler })
    fastify.route({ method: REST_METHODS, url: '/api/*', handler: apiHandler })

    registerMonitoring(fastify, context, { auth })

    // ------------------------------------------------------------------
    // Share links (public)
    // ------------------------------------------------------------------
    if (sharePublicAccess) {
        fastify.route({ method: ['GET', 'HEAD'], url: '/share/:token', handler: async (req, reply) => {
            const share = await context.shares.resolve(req.params.token, {
                password: req.query.password || req.headers['x-share-password'],
            })
            const bucket = await context.repo.findOne('bucket', { id: share.bucketId })
            if (!bucket) throw Object.assign(new Error('The shared bucket no longer exists'), { statusCode: 404 })
            const node = await context.objects.getNode(bucket.id, share.path)
            if (!node || node.deletedAt) throw Object.assign(new Error('The shared object no longer exists'), { statusCode: 404 })
            req.ddrive.shareToken = req.params.token
            req.ddrive.principal = context.iam.anonymousPrincipal()
            if (node.type === 'directory') {
                const children = await context.objects.children(bucket, share.path)
                reply.header('content-type', 'text/html; charset=utf-8')

                return reply.send(shareListingPage(bucket, node, children))
            }
            const version = await context.repo.findOne('object_version', { id: node.latestVersionId })
            const result = await context.objects.stream(version)
            reply.header('content-type', version.contentType || util.contentTypeOf(node.name))
            reply.header('content-length', String(version.size))
            reply.header('content-disposition', util.contentDisposition(node.name, 'inline'))
            reply.header('x-ddrive-version-id', version.id)
            if (req.method === 'GET') await context.shares.recordDownload(share)

            return reply.send(req.method === 'HEAD' ? '' : result.stream)
        } })
    }

    // ------------------------------------------------------------------
    // Static assets: legacy panel at /, console at /console
    // ------------------------------------------------------------------
    fastify.register(FastifyStatic, {
        root: PANEL_DIR,
        index: ['index.html'],
        cacheControl: false,
    })
    if (config.servers.console.enabled !== false) {
        fastify.register(FastifyStatic, {
            root: CONSOLE_DIR,
            prefix: '/console/',
            index: ['index.html'],
            decorateReply: false,
            cacheControl: false,
        })
        fastify.route({ method: ['GET', 'HEAD'], url: '/console', handler: (req, reply) => reply.redirect('/console/') })
    }

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    fastify.setErrorHandler((error, req, reply) => {
        const protocol = req.ddrive?.protocol
        if (error.validation) {
            error.statusCode = 400
            error.code = 'InvalidRequest'
        }
        if (protocol === 's3') return s3Server.sendError(req, reply, error)
        if (protocol === 'webdav') return sendDavError(req, reply, error)
        const statusCode = error.statusCode || 500
        if (statusCode >= 500) {
            fastify.log.error({ err: error, url: req.url }, 'request failed')
        } else if (error.expose !== false && !error.statusCode) {
            error.statusCode = statusCode
        }
        reply.code(statusCode)

        return reply.send({
            message: error.expose === false || statusCode >= 500 ? 'Internal server error' : error.message,
            code: error.code || undefined,
        })
    })

    fastify.setNotFoundHandler((req, reply) => {
        if (req.ddrive?.protocol === 's3') {
            const err = new Error(`The specified path does not exist: ${req.ddrive.rawPath}`)
            err.statusCode = 404
            err.code = 'NoSuchKey'

            return s3Server.sendError(req, reply, err)
        }
        reply.code(404)

        return reply.send({ message: 'Not found' })
    })

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------
    let bootstrapped = false
    const bootstrap = async () => {
        if (bootstrapped) return
        if (!opts.context) await context.bootstrap()
        context.startWorkers()
        bootstrapped = true
    }
    // `listen()`/`ready()` bootstraps the database and starts the workers, so
    // returning the bare fastify instance (legacy HttpServer API) keeps working.
    fastify.addHook('onReady', bootstrap)

    const start = async () => {
        await fastify.listen({ host: config.servers.host, port: config.servers.port })

        return fastify
    }

    const stop = async () => {
        context.stopWorkers()
        await fastify.close()
        await context.close()
    }

    return {
        fastify, context, auth, s3Server, webdavServer, restServer, start, stop, VERSION,
    }
}

const sendDavError = (req, reply, error) => {
    const statusCode = error.statusCode || 500
    if (statusCode === 401 && !reply.getHeader('www-authenticate')) {
        reply.header('WWW-Authenticate', 'Basic realm="DDrive"')
    }
    const message = statusCode >= 500 || error.expose === false ? 'Internal server error' : (error.message || 'Error')
    reply.code(statusCode).header('content-type', 'application/xml; charset=utf-8')
    if (req.method === 'HEAD') return reply.send('')

    return reply.send(`<?xml version="1.0" encoding="UTF-8"?>\n<D:error xmlns:D="DAV:"><D:message>${util.escapeXml(message)}</D:message></D:error>`)
}

const shareListingPage = (bucket, node, children) => {
    const rows = children.map((child) => {
        const name = child.name + (child.type === 'directory' ? '/' : '')
        const href = child.type === 'directory' ? `${encodeURIComponent(child.name)}/` : encodeURIComponent(child.name)
        const size = child.type === 'directory' ? '' : util.humanBytes(Number(child.size || 0))

        return `<tr><td><a href="${href}">${util.escapeXml(name)}</a></td><td>${size}</td><td>${util.iso(child.updatedAt || child.createdAt)}</td></tr>`
    }).join('')

    return `<!doctype html><html><head><meta charset="utf-8"><title>${util.escapeXml(node.name)} — DDrive share</title>
<style>body{font:14px system-ui;background:#0f1116;color:#e8eaf0;padding:32px}table{border-collapse:collapse;width:100%;max-width:900px}
td,th{padding:8px 10px;border-bottom:1px solid #262b36;text-align:left}th{color:#8b93a7;text-transform:uppercase;font-size:12px}a{color:#4c8dff;text-decoration:none}</style>
</head><body><h1>${util.escapeXml(bucket.name)}/${util.escapeXml(node.path)}</h1>
<table><thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead><tbody>${rows || '<tr><td colspan="3">Empty</td></tr>'}</tbody></table></body></html>`
}

module.exports = { createHttpServer, HTTP_METHODS, DAV_METHODS, S3_METHODS, REST_METHODS, createContext, VERSION }
