/**
 * Request authentication for every DDrive surface.
 *
 * Supported credential types (evaluated in order):
 *   1. AWS Signature V4   - header or presigned query (S3 API, replication)
 *   2. Basic auth         - humans: WebDAV, console, legacy REST panel
 *   3. Bearer session     - console SPA (HMAC signed token issued by /api/login)
 *   4. Share link token   - anonymous, read only, scoped to one object
 *
 * The result is always a *principal* + `authorize()` helper, so route handlers
 * never re-implement authorization.
 */
const { errors, StorageError } = require('../lib/errors')
const sigv4 = require('../lib/sigv4')

const parseBasic = (header) => {
    if (!header || !/^basic /i.test(header)) return null
    const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString()
    const idx = decoded.indexOf(':')
    if (idx === -1) return null

    return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) }
}

const createAuth = (context) => {
    const {
        iam, repo, crypto, config, audit, shares,
    } = context

    /** Resolve the principal attached to a request, or null for anonymous. */
    const principalFor = async (req) => {
        const headers = req.headers
        const authorization = headers.authorization || ''
        const protocol = req.ddrive?.protocol

        // ---------------------------------------------------------- SigV4
        const isPresigned = req.query && (req.query['X-Amz-Algorithm'] === sigv4.ALGORITHM || req.query['X-Amz-Signature'])
        if (/^AWS4-HMAC-SHA256/i.test(authorization) || isPresigned) {
            const url = new URL(req.url, 'http://internal')
            // The access key id is inside the credential scope, so it is read
            // first and its secret used to verify the signature.
            const credential = sigv4.parseAuthorization(authorization)?.Credential
                || url.searchParams.get('X-Amz-Credential') || ''
            const accessKeyId = String(credential).split('/')[0]
            const resolved = accessKeyId ? await iam.resolveAccessKey(accessKeyId) : null
            if (!resolved) throw new StorageError('InvalidAccessKeyId', 'The access key id you provided does not exist or is disabled', { statusCode: 403 })
            const verified = sigv4.verifyRequest({
                method: req.method,
                rawPath: req.ddrive?.rawPath || url.pathname,
                query: url.searchParams,
                headers,
                payloadHash: headers['x-amz-content-sha256'],
            }, { secret: resolved.secretAccessKey, region: config.servers.s3.region })
            const user = await repo.findOne('user', { id: resolved.key.userId })
            if (!user || user.status !== 'active') throw errors.accessDenied('The user for this access key is disabled')
            await repo.update('access_key', { id: resolved.key.id }, {
                lastUsedAt: new Date(), lastUsedIp: req.ddrive?.ip || req.ip,
            }).catch(() => {})
            const principal = await iam.buildPrincipal(user, { type: 'access-key' })
            principal.accessKeyId = verified.accessKeyId
            principal.authType = 'sigv4'
            // kept so the S3 server can verify aws-chunked payload signatures
            req.ddrive = req.ddrive || {}
            req.ddrive.sigv4 = {
                signingKey: verified.signingKey,
                amzDate: verified.amzDate,
                dateStamp: verified.dateStamp,
                region: verified.scope.region,
                service: verified.scope.service,
                payloadHash: verified.payloadHash,
                presigned: verified.isPresigned,
            }

            return principal
        }

        // ---------------------------------------------------------- share link
        const shareToken = req.query?.token || req.ddrive?.shareToken
        if (shareToken && !authorization) {
            const share = await shares.resolve(shareToken, { password: req.query?.password || headers['x-share-password'] })
            const principal = iam.anonymousPrincipal()
            principal.share = share
            principal.documents = [{
                Version: '2012-10-17',
                Statement: [{
                    Effect: 'Allow', Action: ['s3:GetObject', 's3:GetObjectVersion', 'webdav:Read'], Resource: ['*'],
                }],
            }]
            principal.authType = 'share'

            return principal
        }

        // ---------------------------------------------------------- basic auth
        const basic = parseBasic(authorization)
        if (basic) {
            const user = await iam.verifyPassword(basic.username, basic.password)
            if (!user) {
                await audit?.record({
                    action: 'iam.login', actor: basic.username, actorType: 'user', result: 'denied',
                    protocol, ip: req.ddrive?.ip, requestId: req.id,
                })

                return null
            }
            const principal = await iam.buildPrincipal(user)
            principal.authType = 'basic'

            return principal
        }

        // ---------------------------------------------------------- session token
        const bearer = /^bearer /i.test(authorization) ? authorization.slice(7).trim() : null
        if (bearer) {
            const payload = crypto.verifyToken(bearer, config.security.sessionSecret || undefined)
            if (!payload) throw errors.accessDenied('Session expired, please sign in again')
            const user = await repo.findOne('user', { id: payload.sub })
            if (!user || user.status !== 'active') throw errors.accessDenied('User disabled')
            const principal = await iam.buildPrincipal(user)
            principal.authType = 'session'

            return principal
        }

        // ---------------------------------------------------------- anonymous
        const principal = iam.anonymousPrincipal()

        return principal
    }

    /** Authenticate or throw 401 with the right challenge for the protocol. */
    const requirePrincipal = async (req, reply) => {
        const principal = await principalFor(req).catch((err) => {
            if (err && err.code === 'AccessDenied') return null

            throw err
        })
        if (principal && principal.type !== 'anonymous') return principal
        if (principal && (principal.share || config.security.publicAccess)) return principal

        const err = errors.accessDenied('Authentication required')
        if (req.ddrive?.protocol === 's3') {
            err.statusCode = 403
        } else {
            err.statusCode = 401
            if (reply) reply.header('www-authenticate', 'Basic realm="DDrive", charset="UTF-8"')
        }
        throw err
    }

    /** Authorize a principal for an action on a resource. */
    const authorize = async (req, principal, action, resource) => {
        const target = resource || {}
        const bucketName = target.bucket && typeof target.bucket === 'object' ? target.bucket.name : target.bucket
        let bucketPolicy = null
        if (target.bucket && typeof target.bucket === 'object' && target.bucket.policy !== undefined) {
            bucketPolicy = target.bucket.policy
        } else if (bucketName) {
            const existing = await repo.findOne('bucket', { name: bucketName }).catch(() => null)
            bucketPolicy = existing ? existing.policy : null
        }

        return iam.authorize(principal, action, {
            bucket: bucketName,
            key: target.key,
            arn: target.arn,
        }, {
            ip: req.ddrive?.ip || req.ip,
            secure: req.ddrive?.secure,
            userAgent: req.headers['user-agent'],
            protocol: req.ddrive?.protocol,
            requestId: req.id,
            publicAccess: config.security.publicAccess,
        }, bucketPolicy)
    }

    /** Route guard: authenticate + authorize in one step (fastify preHandler). */
    const guard = (action, resourceFn) => async (req, reply) => {
        const principal = await requirePrincipal(req, reply)
        req.ddrive.principal = principal
        const resource = typeof resourceFn === 'function' ? await resourceFn(req) : (resourceFn || {})
        await authorize(req, principal, action, resource)

        return principal
    }

    /** Console session helpers. */
    const issueSession = (user, opts = {}) => crypto.signToken({
        sub: user.id, username: user.username, isAdmin: !!user.isAdmin,
    }, opts.expiresInSeconds || 43200, config.security.sessionSecret || undefined)

    const login = async (username, password, { mfaCode, ip, requestId, protocol } = {}) => {
        const user = await iam.verifyPassword(username, password)
        if (!user) return null
        const totp = require('../lib/totp')
        if (user.mfaEnabled) {
            if (!mfaCode || !totp.verifyTotp(user.mfaSecret, mfaCode, {})) return false
        }
        const principal = await iam.buildPrincipal(user)
        const token = issueSession(user)
        await audit?.record({
            action: 'iam.login', actor: user.username, actorId: user.id, actorType: 'user', result: 'success', protocol: protocol || 'console', ip, requestId,
        })

        return { token, principal, user }
    }

    return {
        principalFor,
        requirePrincipal,
        authorize,
        guard,
        issueSession,
        login,
        parseBasic,
    }
}

module.exports = { createAuth, parseBasic }
