/**
 * Shared helpers: hashing, etags, XML escaping, ranges, HTTP dates, streams.
 */
const crypto = require('crypto')
const path = require('path')
const mime = require('mime-types')

const iso = (value = new Date()) => {
    if (!value) return null
    const date = value instanceof Date ? value : new Date(value)

    return Number.isNaN(date.getTime()) ? null : date.toISOString()
}

const now = () => new Date()

const addSeconds = (date, seconds) => new Date(date.getTime() + seconds * 1000)
const addDays = (date, days) => addSeconds(date, days * 86400)
const addMs = (date, ms) => new Date(date.getTime() + ms)

const sha256 = (data, encoding = 'hex') => crypto.createHash('sha256').update(data).digest(encoding)
const md5 = (data, encoding = 'hex') => crypto.createHash('md5').update(data).digest(encoding)
const sha1 = (data, encoding = 'hex') => crypto.createHash('sha1').update(data).digest(encoding)
const hmacSha256 = (secret, data, encoding = 'hex') => crypto.createHmac('sha256', secret).update(data).digest(encoding)
const sha256Hmac = hmacSha256

const randomToken = (bytes = 24) => crypto.randomBytes(bytes).toString('base64url')
const randomHex = (bytes = 16) => crypto.randomBytes(bytes).toString('hex')

/**
 * Single source of truth for the administrator/user password policy.
 *
 * Returns an explanation, or null when the password is acceptable. It lives
 * here (and not only in the IAM service) because the bootstrap password in
 * src/config is validated before any service exists - and because a generated
 * password must satisfy exactly the same rules as a typed one.
 */
const passwordPolicyError = (password, username) => {
    const value = String(password || '')
    if (value.length < 8) return 'Password must be at least 8 characters long'
    if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
        return 'Password must contain lower case, upper case and numeric characters'
    }
    if (username && value.toLowerCase().includes(String(username).toLowerCase())) {
        return 'Password must not contain the username'
    }

    return null
}

/**
 * A random password that satisfies `passwordPolicyError`.
 *
 * The candidate is checked before it is returned, because the caller logs this
 * value for the operator: a "generated" password that the policy then silently
 * modified would lock the first administrator out of a fresh install.
 */
const strongPassword = (bytes = 12, username = '') => {
    for (let attempt = 0; attempt < 1000; attempt += 1) {
        // base64url draws lower case, digits and (often) upper case; the second
        // shape is a guaranteed-valid fallback
        const candidate = attempt % 2 === 0 ? randomToken(bytes) : `${randomHex(bytes)}-Aa1x9`
        if (!passwordPolicyError(candidate, username)) return candidate
    }

    throw new Error('could not generate a password that satisfies the password policy')
}

const timingSafeEqual = (a, b) => {
    const bufA = Buffer.from(String(a))
    const bufB = Buffer.from(String(b))
    if (bufA.length !== bufB.length) return false

    return crypto.timingSafeEqual(bufA, bufB)
}

/** Stable stringify (sorted keys) used for audit hashing and SigV4 payloads. */
const canonicalJson = (value) => {
    const walk = (val) => {
        if (val === null || val === undefined) return null
        if (val instanceof Date) return val.toISOString()
        if (Array.isArray(val)) return val.map(walk)
        if (typeof val === 'object') {
            if (Buffer.isBuffer(val)) return val.toString('base64')
            return Object.keys(val).sort().reduce((acc, key) => {
                acc[key] = walk(val[key])

                return acc
            }, {})
        }
        if (typeof val === 'bigint') return Number(val)

        return val
    }

    return JSON.stringify(walk(value))
}

/** Content etag for a single payload (S3 style: quoted md5 hex). */
const etag = (buffer) => md5(buffer)

/** Multipart etag: md5 of the concatenated binary part md5s, suffixed with -N. */
const multipartEtag = (partMd5Hexes) => {
    const binary = partMd5Hexes.map((hex) => Buffer.from(hex, 'hex'))
    const digest = md5(Buffer.concat(binary))
    const etagValue = `${digest}-${partMd5Hexes.length}`

    return etagValue
}

/**
 * Compute the etag for a chunked object without loading the whole file into
 * memory. Uses the S3 rule: if the object has a single part the etag is the md5
 * of the content, otherwise md5-of-md5s with a -N suffix.
 */
const combinedEtag = (chunkHashes) => (chunkHashes.length === 1 ? chunkHashes[0] : multipartEtag(chunkHashes))

const escapeXml = (value) => String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
    // strip control chars that are invalid in XML 1.0
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '')

/** RFC 1123 date, e.g. Tue, 15 Nov 1994 08:12:31 GMT */
const httpDate = (date = new Date()) => new Date(date).toUTCString()

const parseHttpDate = (value) => {
    const ts = Date.parse(value)

    return Number.isNaN(ts) ? null : new Date(ts)
}

/**
 * Parse an HTTP Range header against a known object size.
 * Returns null when the header is absent or malformed (caller ignores the
 * header) or throws for a syntactically valid but unsatisfiable range.
 */
const parseRange = (header, size) => {
    if (!header || typeof header !== 'string') return null
    const match = /^bytes=(.*)$/i.exec(header.trim())
    if (!match) return null
    const spec = match[1].split(',')[0].trim()
    const [startRaw, endRaw] = spec.split('-')
    if (startRaw === '' && endRaw === '') return null
    let start
    let end
    if (startRaw === '') {
        const suffix = parseInt(endRaw, 10)
        if (!Number.isFinite(suffix) || suffix < 0) return null
        if (suffix === 0) throw new Error('unsatisfiable')
        start = Math.max(0, size - suffix)
        end = size - 1
    } else {
        start = parseInt(startRaw, 10)
        end = endRaw === '' ? size - 1 : parseInt(endRaw, 10)
    }
    if (!Number.isFinite(start) || !Number.isFinite(end)) return null
    if (start > end || start >= size) throw new Error('unsatisfiable')
    end = Math.min(end, size - 1)

    return { start, end, length: end - start + 1 }
}

const INLINE_TYPES = new Set([
    'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'audio/mpeg', 'audio/mp4',
    'audio/ogg', 'audio/wav', 'audio/webm', 'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'image/svg+xml', 'image/avif', 'application/pdf', 'text/plain', 'text/markdown', 'text/csv',
])

const contentTypeOf = (filename) => mime.lookup(path.extname(String(filename || ''))) || 'application/octet-stream'
const isInlineType = (contentType) => INLINE_TYPES.has(String(contentType || '').split(';')[0].trim())

/** RFC 5987 / RFC 6266 safe Content-Disposition value. */
const contentDisposition = (filename, disposition = 'attachment') => {
    const name = String(filename || 'download').replace(/[\r\n"]/g, '')
    const ascii = name.replace(/[^\x20-\x7E]/g, '_')

    return `${disposition}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`
}

/** Normalize an object key: no leading slash, no empty/`.`/`..` segments. */
const normalizeKey = (key) => {
    const parts = String(key || '')
        .replace(/\\/g, '/')
        .split('/')
        .filter((p) => p && p !== '.' && p !== '..')

    return parts.join('/')
}

/** Normalize a request path (decoded) into an absolute clean path. */
const normalizePath = (value) => {
    const decoded = decodeURIComponentSafe(value)
    const parts = decoded.replace(/\\/g, '/').split('/').filter((p) => p && p !== '.')

    return `/${parts.join('/')}`
}

const decodeURIComponentSafe = (value) => {
    try {
        return decodeURIComponent(value)
    } catch {
        return value
    }
}

const isSubPath = (parent, child) => {
    const p = parent.endsWith('/') ? parent : `${parent}/`

    return child === parent || child.startsWith(p)
}

const parentPath = (value) => {
    const normalized = normalizeKey(value)
    const idx = normalized.lastIndexOf('/')

    return idx === -1 ? '' : normalized.slice(0, idx)
}

const basename = (value) => {
    const normalized = normalizeKey(value)

    return normalized.slice(normalized.lastIndexOf('/') + 1)
}

const humanBytes = (bytes) => {
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
    let value = Number(bytes) || 0
    let unit = 0
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024
        unit += 1
    }

    return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

const isStream = (value) => !!value && typeof value.pipe === 'function' && typeof value.on === 'function'

const streamToBuffer = (stream, { limit = 0 } = {}) => new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    stream.on('data', (chunk) => {
        size += chunk.length
        if (limit && size > limit) {
            const err = new Error(`The request body exceeds the ${limit} byte limit`)
            err.statusCode = 413
            err.code = 'EntityTooLarge'
            stream.destroy?.()
            reject(err)

            return
        }
        chunks.push(chunk)
    })
    stream.on('end', () => resolve(Buffer.concat(chunks)))
    stream.on('error', reject)
})

/**
 * The request body as a stream.
 *
 * Fastify only runs content type parsers for the standard HTTP methods, so
 * WebDAV verbs (PROPFIND, PROPPATCH, LOCK, ...) never get `req.body` set: fall
 * back to the raw socket stream whenever the request declares a body.
 */
const requestStream = (req) => {
    const body = req.body
    if (isStream(body)) return body
    if (Buffer.isBuffer(body) || body instanceof Uint8Array) return bufferToStream(Buffer.from(body))
    if (typeof body === 'string') return bufferToStream(Buffer.from(body))
    const headers = req.headers || {}
    const hasBody = headers['content-length'] !== undefined || headers['transfer-encoding'] !== undefined
    if (hasBody && req.raw && !req.raw.readableEnded) return req.raw

    return bufferToStream(Buffer.alloc(0))
}

const readBody = async (req, { limit = 0 } = {}) => {
    const body = req.body
    if (body === undefined || body === null) {
        const headers = req.headers || {}
        if (headers['content-length'] !== undefined || headers['transfer-encoding'] !== undefined) {
            return streamToBuffer(requestStream(req), { limit })
        }

        return Buffer.alloc(0)
    }
    if (Buffer.isBuffer(body)) return body
    if (body instanceof Uint8Array) return Buffer.from(body)
    if (typeof body === 'string') return Buffer.from(body)
    if (isStream(body)) return streamToBuffer(body, { limit })

    return Buffer.from(JSON.stringify(body))
}

const bodyText = async (req, opts) => (await readBody(req, opts)).toString('utf8')

const jsonBody = async (req, opts) => {
    const text = (await bodyText(req, opts)).trim()
    if (!text) return {}
    try {
        return JSON.parse(text)
    } catch (err) {
        const { errors } = require('./errors')

        throw errors.invalidArgument(`Malformed JSON body: ${err.message}`)
    }
}

/** Request body as a readable stream (parsed bodies are wrapped again). */
const bodyStream = (req) => {
    const body = req.body
    if (isStream(body)) return body
    if (Buffer.isBuffer(body) || typeof body === 'string' || body instanceof Uint8Array) return bufferToStream(Buffer.from(body))
    if (body !== undefined && body !== null) return bufferToStream(Buffer.from(JSON.stringify(body)))
    const headers = req.headers || {}
    const hasBody = headers['content-length'] !== undefined || headers['transfer-encoding'] !== undefined
    if (hasBody && req.raw) return req.raw

    return req.raw || bufferToStream(Buffer.alloc(0))
}

const bufferToStream = (buffer) => {
    const { Readable } = require('stream')

    return Readable.from([buffer])
}

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms) })

/** Retry with exponential backoff + jitter (used by replication and events). */
const retry = async (fn, opts = {}) => {
    const {
        attempts = 5, baseDelayMs = 250, maxDelayMs = 30000, onError, shouldRetry = () => true,
    } = opts
    let lastError
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
        try {
            // eslint-disable-next-line no-await-in-loop
            return await fn(attempt)
        } catch (err) {
            lastError = err
            if (onError) onError(err, attempt)
            if (attempt === attempts || !shouldRetry(err, attempt)) break
            const delay = Math.min(maxDelayMs, baseDelayMs * (2 ** (attempt - 1)))
            const jitter = Math.floor(Math.random() * (delay / 4 + 1))
            // eslint-disable-next-line no-await-in-loop
            await sleep(delay + jitter)
        }
    }
    throw lastError
}

const parseDuration = (value) => {
    if (typeof value === 'number') return value
    const match = /^\s*(\d+)\s*(ms|s|m|h|d)?\s*$/i.exec(String(value || ''))
    if (!match) return null
    const amount = parseInt(match[1], 10)
    const unit = (match[2] || 's').toLowerCase()
    const factor = {
        ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000,
    }[unit]

    return amount * factor
}

const chunkArray = (arr, size) => {
    const out = []
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size))

    return out
}

const uniqueBy = (arr, fn) => {
    const seen = new Set()

    return arr.filter((item) => {
        const key = fn(item)
        if (seen.has(key)) return false
        seen.add(key)

        return true
    })
}

/** AWS SigV4 wants `YYYYMMDDTHHMMSSZ`. */
const amzDate = (date = new Date()) => date.toISOString().replace(/[:-]|\.\d{3}/g, '')

const credentialScope = (date, region, service = 's3') => `${amzDate(date).slice(0, 8)}/${region}/${service}/aws4_request`

module.exports = {
    requestStream,
    iso,
    now,
    addSeconds,
    addDays,
    addMs,
    sha256,
    md5,
    sha1,
    hmacSha256,
    sha256Hmac,
    randomToken,
    randomHex,
    passwordPolicyError,
    strongPassword,
    timingSafeEqual,
    canonicalJson,
    etag,
    multipartEtag,
    combinedEtag,
    escapeXml,
    httpDate,
    parseHttpDate,
    parseRange,
    contentTypeOf,
    isInlineType,
    contentDisposition,
    normalizeKey,
    normalizePath,
    decodeURIComponentSafe,
    isSubPath,
    parentPath,
    basename,
    humanBytes,
    streamToBuffer,
    isStream,
    readBody,
    bodyText,
    jsonBody,
    bodyStream,
    bufferToStream,
    sleep,
    retry,
    parseDuration,
    chunkArray,
    uniqueBy,
    amzDate,
    credentialScope,
    INLINE_TYPES,
}
