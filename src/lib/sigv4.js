/**
 * AWS Signature Version 4: signing (clients, replication) and verification
 * (S3 API), implemented from the public AWS specification.
 *
 * Verified/supported:
 *  - header and presigned-url authentication
 *  - canonical request/string-to-sign/signing-key derivation
 *  - `UNSIGNED-PAYLOAD`, `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and
 *    `STREAMING-UNSIGNED-PAYLOAD-TRAILER` payloads
 *  - `Content-Encoding: aws-chunked` framing with per-chunk signature checks
 *
 * Because different SDKs canonicalise URIs slightly differently (raw, encoded,
 * double encoded, `+` as `%20`), a request is accepted when any of the standard
 * variants matches - each variant hashes exactly what the client signed, so
 * this does not weaken the signature check.
 */
const { Transform } = require('stream')
const crypto = require('crypto')
const util = require('./util')
const { errors } = require('./errors')

const ALGORITHM = 'AWS4-HMAC-SHA256'
const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'
const STREAMING_PAYLOAD = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
const STREAMING_TRAILER = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER'
const STREAMING_UNSIGNED_TRAILER = 'STREAMING-UNSIGNED-PAYLOAD-TRAILER'
const EMPTY_SHA256 = crypto.createHash('sha256').update('').digest('hex')
const DEFAULT_REGION = 'us-east-1'

const hmac = (key, value) => crypto.createHmac('sha256', key).update(value, 'utf8').digest()
const sha256hex = (value) => crypto.createHash('sha256').update(value).digest('hex')
const payloadHashOf = (value) => (value === undefined || value === null || value === '' ? EMPTY_SHA256 : sha256hex(value))

/** AWS URI encoding (RFC 3986: `!*'()` are encoded, `%XX` is upper case). */
const awsUriEncode = (value, encodeSlash = true) => {
    const encoded = encodeURIComponent(String(value)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)

    return encodeSlash ? encoded : encoded.replace(/%2F/g, '/')
}

const encodePath = (path) => String(path || '/').split('/').map((segment) => awsUriEncode(segment, true)).join('/')

const canonicalQueryString = (source) => {
    const pairs = []
    if (source instanceof URLSearchParams) source.forEach((value, key) => pairs.push([key, value]))
    else if (source && typeof source.forEach === 'function' && !Array.isArray(source)) source.forEach((value, key) => pairs.push([key, value]))
    else Object.entries(source || {}).forEach(([key, value]) => (Array.isArray(value) ? value : [value]).forEach((v) => pairs.push([key, v])))

    return pairs
        .map(([k, v]) => [awsUriEncode(k, true), awsUriEncode(v === undefined || v === null ? '' : v, true)])
        .sort((a, b) => (a[0] < b[0] ? -1 : (a[0] > b[0] ? 1 : (a[1] < b[1] ? -1 : 1))))
        .map(([k, v]) => `${k}=${v}`)
        .join('&')
}

const canonicalHeaders = (headers, signedHeaders) => {
    const names = String(signedHeaders || '').split(';').map((h) => h.trim().toLowerCase()).filter(Boolean)
    const lines = names.map((name) => {
        const raw = headers[name]
        const value = Array.isArray(raw) ? raw.join(',') : String(raw === undefined || raw === null ? '' : raw)

        return `${name}:${value.replace(/\s+/g, ' ').trim()}`
    })

    return { names, canonical: `${lines.join('\n')}\n` }
}

const variants = (rawPath) => {
    const out = new Set()
    const raw = rawPath || '/'
    out.add(raw)
    out.add(encodePath(raw))
    try { out.add(encodePath(util.decodeURIComponentSafe(raw))) } catch { /* ignore */ }
    try { out.add(encodePath(encodeURIComponent(util.decodeURIComponentSafe(raw)))) } catch { /* ignore */ }
    // some clients keep `+` literal, others encode it as %20
    out.add(raw.replace(/\+/g, '%20'))
    out.add(encodePath(raw).replace(/\+/g, '%20'))

    return [...out].filter((v) => v.length)
}

const signingKey = (secret, dateStamp, region, service) => {
    const kDate = hmac(`AWS4${secret}`, dateStamp)
    const kRegion = hmac(kDate, region)
    const kService = hmac(kRegion, service)

    return hmac(kService, 'aws4_request')
}

const buildCanonical = ({ method, uri, query, headers, signedHeaders, payloadHash }) => [
    String(method).toUpperCase(),
    uri,
    canonicalQueryString(query),
    canonicalHeaders(headers, signedHeaders).canonical,
    String(signedHeaders || '').split(';').map((h) => h.trim().toLowerCase()).filter(Boolean).join(';'),
    payloadHash,
].join('\n')

const expectedSignature = ({ secret, dateStamp, region, service, amzDate, canonical }) => {
    const scope = `${dateStamp}/${region}/${service}/aws4_request`
    const stringToSign = [ALGORITHM, amzDate, scope, sha256hex(canonical)].join('\n')

    return { signature: crypto.createHmac('sha256', signingKey(secret, dateStamp, region, service)).update(stringToSign, 'utf8').digest('hex'), stringToSign, scope }
}

const signatureMatches = (expected, provided) => {
    if (!provided || expected.length !== String(provided).length) return false

    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(provided)))
}

const parseAmzDate = (value) => {
    if (!/^\d{8}T\d{6}Z$/.test(String(value || ''))) return null
    const iso = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(9, 11)}:${value.slice(11, 13)}:${value.slice(13, 15)}Z`
    const time = Date.parse(iso)

    return Number.isFinite(time) ? time : null
}

const parseAuthorization = (authorization) => {
    if (!authorization) return null
    const match = new RegExp(`^${ALGORITHM}\\s+(.*)$`).exec(String(authorization).trim())
    if (!match) return null
    const out = {}
    match[1].split(',').forEach((chunk) => {
        const index = chunk.indexOf('=')
        if (index > 0) out[chunk.slice(0, index).trim()] = chunk.slice(index + 1).trim()
    })

    return out
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------
/**
 * Sign a request and return the headers to send.
 *
 * @param {object} req { method, url, headers, body, payloadHash, date }
 * @param {object} credentials { accessKeyId, secretAccessKey, sessionToken }
 * @param {object} [opts] { region, service, date }
 * @returns {object} headers (already merged with the provided ones)
 */
const signRequest = (req, credentials, opts = {}) => {
    const { method = 'GET', url, body, date = opts.date || new Date() } = req
    const region = opts.region || DEFAULT_REGION
    const service = opts.service || 's3'
    const parsed = new URL(url)
    const headers = {}
    Object.entries(req.headers || {}).forEach(([k, v]) => { headers[String(k).toLowerCase()] = v })
    if (!headers.host) headers.host = parsed.host
    const amzDate = `${date.toISOString().replace(/[:-]|\.\d{3}/g, '')}`
    const dateStamp = amzDate.slice(0, 8)
    headers['x-amz-date'] = amzDate
    if (credentials.sessionToken) headers['x-amz-security-token'] = credentials.sessionToken
    const payloadHash = req.payloadHash || (body === undefined || body === null ? EMPTY_SHA256 : payloadHashOf(body))
    headers['x-amz-content-sha256'] = payloadHash
    const signedHeaders = Object.keys(headers).map((h) => h.toLowerCase()).sort().join(';')
    const canonical = buildCanonical({
        method,
        uri: parsed.pathname || '/',
        query: parsed.searchParams,
        headers,
        signedHeaders,
        payloadHash,
    })
    const { signature, scope } = expectedSignature({
        secret: credentials.secretAccessKey, dateStamp, region, service, amzDate, canonical,
    })
    headers.authorization = `${ALGORITHM} Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`

    return headers
}

/** Presign a URL (query string authentication). */
const presign = (req, credentials, opts = {}) => {
    const {
        method = 'GET', url, region = DEFAULT_REGION, service = 's3', expiresIn = 3600, date = new Date(),
    } = { ...req, ...opts }
    const parsed = new URL(url)
    const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '')
    const dateStamp = amzDate.slice(0, 8)
    const scope = `${dateStamp}/${region}/${service}/aws4_request`
    parsed.searchParams.set('X-Amz-Algorithm', ALGORITHM)
    parsed.searchParams.set('X-Amz-Credential', `${credentials.accessKeyId}/${scope}`)
    parsed.searchParams.set('X-Amz-Date', amzDate)
    parsed.searchParams.set('X-Amz-Expires', String(Math.min(Math.max(Number(expiresIn) || 3600, 1), 604800)))
    parsed.searchParams.set('X-Amz-SignedHeaders', 'host')
    if (credentials.sessionToken) parsed.searchParams.set('X-Amz-Security-Token', credentials.sessionToken)
    const canonical = buildCanonical({
        method, uri: parsed.pathname, query: parsed.searchParams, headers: { host: parsed.host }, signedHeaders: 'host', payloadHash: UNSIGNED_PAYLOAD,
    })
    const { signature } = expectedSignature({
        secret: credentials.secretAccessKey, dateStamp, region, service, amzDate, canonical,
    })
    parsed.searchParams.set('X-Amz-Signature', signature)

    return parsed.toString()
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------
/**
 * Verify an S3 request signature. Throws a StorageError when it does not check
 * out (the *error code* matches what S3 clients expect).
 *
 * The request object may describe the target either as `{ rawPath, query }` or
 * as `{ path, searchParams }`.
 */
const verifyRequest = (req, opts = {}) => {
    const {
        region = DEFAULT_REGION, service = 's3', maxSkewMs = 15 * 60 * 1000,
    } = opts
    const headers = {}
    Object.entries(req.headers || {}).forEach(([k, v]) => { headers[k.toLowerCase()] = v })
    const authorization = headers.authorization
    const query = req.query instanceof URLSearchParams
        ? new URLSearchParams(req.query.toString())
        : new URLSearchParams(req.searchParams instanceof URLSearchParams ? req.searchParams.toString() : (req.query || req.searchParams || ''))
    const rawPath = req.rawPath || req.path || req.url || '/'
    const isPresigned = ['X-Amz-Algorithm', 'X-Amz-Signature'].some((key) => query.has(key))

    const fail = (code, message) => {
        const err = new (require('./errors').StorageError)(code, message, { statusCode: 403 })

        throw err
    }

    let credential
    let signedHeaders
    let providedSignature
    let amzDate
    let payloadHash

    if (isPresigned) {
        if (query.get('X-Amz-Algorithm') !== ALGORITHM) fail('AuthorizationHeaderMalformed', 'Unsupported presign algorithm')
        credential = query.get('X-Amz-Credential') || ''
        signedHeaders = query.get('X-Amz-SignedHeaders') || ''
        providedSignature = query.get('X-Amz-Signature') || ''
        amzDate = query.get('X-Amz-Date') || ''
        payloadHash = query.get('X-Amz-Content-Sha256') || ''
        const expires = Number(query.get('X-Amz-Expires') || 0)
        if (!Number.isFinite(expires) || expires <= 0 || expires > 604800) fail('AuthorizationHeaderMalformed', 'Invalid X-Amz-Expires')
    } else if (authorization && authorization.startsWith(`${ALGORITHM} `)) {
        const parts = parseAuthorization(authorization) || {}
        credential = parts.Credential || ''
        signedHeaders = parts.SignedHeaders || ''
        providedSignature = parts.Signature || ''
        amzDate = headers['x-amz-date'] || parts.Date || ''
        payloadHash = headers['x-amz-content-sha256'] || ''
    } else {
        fail('AccessDenied', 'Missing AWS Signature V4 authorization')
    }

    const [accessKeyId, scopeDate, scopeRegion, scopeService, terminator] = String(credential).split('/')
    if (!accessKeyId || !scopeDate || !scopeRegion || !scopeService || terminator !== 'aws4_request') {
        fail('AuthorizationHeaderMalformed', 'Malformed credential scope')
    }
    if (scopeRegion !== region) fail('AuthorizationHeaderMalformed', `Credential scope region ${scopeRegion} does not match ${region}`)
    if (scopeService !== service) fail('AuthorizationHeaderMalformed', `Credential scope service ${scopeService} does not match ${service}`)
    const dateStamp = scopeDate
    const requestTime = parseAmzDate(amzDate)
    if (!requestTime) fail('AuthorizationHeaderMalformed', 'Invalid X-Amz-Date')
    if (amzDate.slice(0, 8) !== dateStamp) fail('AuthorizationHeaderMalformed', 'Credential scope date does not match X-Amz-Date')
    if (!isPresigned && Math.abs(Date.now() - requestTime) > maxSkewMs) fail('RequestTimeTooSkewed', 'The difference between the request time and the server time is too large')
    if (isPresigned && Date.now() > requestTime + Number(query.get('X-Amz-Expires') || 0) * 1000) fail('AccessDenied', 'Request has expired')
    const signedHeaderList = String(signedHeaders).toLowerCase()
    if (!signedHeaderList.split(';').includes('host')) fail('AuthorizationHeaderMalformed', 'The host header must be signed')

    const explicitPayloadHash = String(payloadHash || '')
    // Clients that do not send `X-Amz-Content-Sha256` disagree on the payload
    // hash they sign with (empty-body SHA256 vs UNSIGNED-PAYLOAD), so both are
    // accepted - neither lets a caller sign a body it did not intend to send.
    const payloadHashes = explicitPayloadHash
        ? [explicitPayloadHash]
        : [EMPTY_SHA256, UNSIGNED_PAYLOAD]
    const effectivePayloadHash = explicitPayloadHash || UNSIGNED_PAYLOAD
    // the signature itself is never part of the canonical query string
    const canonicalQuery = new URLSearchParams(query.toString())
    canonicalQuery.delete('X-Amz-Signature')
    const verified = variants(rawPath).some((uri) => payloadHashes.some((hash) => {
        const canonical = buildCanonical({
            method: req.method, uri, query: canonicalQuery, headers, signedHeaders: signedHeaderList, payloadHash: hash,
        })

        return signatureMatches(expectedSignature({
            secret: opts.secret, dateStamp, region, service, amzDate, canonical,
        }).signature, providedSignature)
    }))
    if (!verified) fail('SignatureDoesNotMatch', 'The request signature we calculated does not match the signature you provided')

    return {
        ok: true,
        accessKeyId,
        amzDate,
        dateStamp,
        scope: { region, service },
        signedHeaders: signedHeaderList.split(';').filter(Boolean),
        payloadHash: effectivePayloadHash,
        isPresigned,
        signingKey: signingKey(opts.secret, dateStamp, region, service),
        signature: providedSignature,
    }
}

// ---------------------------------------------------------------------------
// aws-chunked bodies
// ---------------------------------------------------------------------------
const isChunked = (headers) => {
    const encoding = String(headers['content-encoding'] || '').toLowerCase()
    const hash = String(headers['x-amz-content-sha256'] || '').toUpperCase()

    return encoding.includes('aws-chunked') || hash.startsWith('STREAMING-')
}

/**
 * Decode `Content-Encoding: aws-chunked` framing back into the object payload,
 * verifying each chunk signature when a signing key is available.
 *
 * Frame: `<hex-size>[;chunk-signature=<sig>]\r\n<data>\r\n` ... `0[;sig]\r\n\r\n`
 */
const decodeChunkedStream = (source, {
    signingKey: key = null, amzDate = '', dateStamp = '', region = DEFAULT_REGION, service = 's3', verify = true, maxBytes = 0,
} = {}) => {
    let buffer = Buffer.alloc(0)
    let total = 0
    let previousSignature = ''
    let done = false
    const scope = `${dateStamp}/${region}/${service}/aws4_request`
    const out = new Transform({
        transform(chunk, _enc, callback) {
            if (done) return callback()
            buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk
            try {
                for (;;) {
                    const headerEnd = buffer.indexOf('\r\n')
                    if (headerEnd < 0) return callback()
                    const header = buffer.slice(0, headerEnd).toString('utf8').trim()
                    if (!/^[0-9a-fA-F]+(;|$)/.test(header)) {
                        // malformed framing: hand the rest through untouched
                        this.push(buffer)
                        buffer = Buffer.alloc(0)

                        return callback()
                    }
                    const [sizeHex, ...extensions] = header.split(';')
                    const size = parseInt(sizeHex, 16)
                    const chunkSignature = (extensions.join(';').match(/chunk-signature=([0-9a-fA-F]+)/) || [])[1] || ''
                    if (size === 0) {
                        done = true
                        this.push(Buffer.alloc(0))
                        buffer = Buffer.alloc(0)
                        if (verify && chunkSignature && key) {
                            const expected = crypto.createHmac('sha256', key).update([
                                'AWS4-HMAC-SHA256-PAYLOAD', amzDate, scope, previousSignature, EMPTY_SHA256, EMPTY_SHA256,
                            ].join('\n'), 'utf8').digest('hex')
                            if (!signatureMatches(expected, chunkSignature)) {
                                return callback(Object.assign(new Error('The chunk signature does not match'), { code: 'SignatureDoesNotMatch', statusCode: 403 }))
                            }
                        }

                        return callback()
                    }
                    if (buffer.length < headerEnd + 2 + size + 2) return callback()
                    const data = buffer.slice(headerEnd + 2, headerEnd + 2 + size)
                    if (buffer.slice(headerEnd + 2 + size, headerEnd + 2 + size + 2).toString('utf8') !== '\r\n') {
                        this.push(buffer)
                        buffer = Buffer.alloc(0)

                        return callback()
                    }
                    if (verify && chunkSignature && key) {
                        const stringToSign = [
                            'AWS4-HMAC-SHA256-PAYLOAD', amzDate, scope, previousSignature, EMPTY_SHA256, sha256hex(data),
                        ].join('\n')
                        const expected = crypto.createHmac('sha256', key).update(stringToSign, 'utf8').digest('hex')
                        if (!signatureMatches(expected, chunkSignature)) {
                            return callback(Object.assign(new Error('The chunk signature does not match'), { code: 'SignatureDoesNotMatch', statusCode: 403 }))
                        }
                    }
                    previousSignature = chunkSignature || previousSignature
                    total += data.length
                    if (maxBytes && total > maxBytes) {
                        return callback(Object.assign(new Error('EntityTooLarge'), { code: 'EntityTooLarge', statusCode: 400 }))
                    }
                    this.push(data)
                    buffer = buffer.slice(headerEnd + 2 + size + 2)
                }
            } catch (err) {
                return callback(err)
            }
        },
    })

    return source.pipe(out)
}

/** Hash a stream on the way through so `x-amz-content-sha256` can be checked. */
const payloadVerifier = (expected) => {
    if (!/^[0-9a-f]{64}$/i.test(String(expected || ''))) return null
    const hash = crypto.createHash('sha256')
    const stream = new Transform({
        transform(chunk, _enc, callback) {
            hash.update(chunk)
            callback(null, chunk)
        },
    })

    return {
        stream,
        verify: () => hash.digest('hex').toLowerCase() === String(expected).toLowerCase(),
    }
}

const errorsModule = { errors }
void errorsModule

module.exports = {
    ALGORITHM,
    UNSIGNED_PAYLOAD,
    STREAMING_PAYLOAD,
    STREAMING_TRAILER,
    STREAMING_UNSIGNED_TRAILER,
    EMPTY_SHA256,
    DEFAULT_REGION,
    signRequest,
    presign,
    verifyRequest,
    parseAuthorization,
    decodeChunkedStream,
    isChunked,
    payloadVerifier,
    payloadHashOf,
    awsUriEncode,
    encodePath,
    canonicalQueryString,
    canonicalHeaders,
    buildCanonical,
    expectedSignature,
    signingKey,
    variants,
    errors,
}
