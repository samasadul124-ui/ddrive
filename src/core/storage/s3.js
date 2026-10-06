/**
 * Remote S3-compatible chunk store (client).
 *
 * Used for the COOL / ARCHIVE tiers and as a replication target: chunks are
 * stored as individual objects in any S3 compatible service (AWS S3, MinIO,
 * Ceph RGW, Cloudflare R2, Wasabi, Backblaze B2, ...). Requests are signed with
 * our own SigV4 implementation (src/lib/sigv4.js).
 */
const crypto = require('crypto')
const { Readable } = require('stream')
const { errors } = require('../../lib/errors')
const sigv4 = require('../../lib/sigv4')

const createS3Store = (opts = {}) => {
    const endpoint = String(opts.endpoint || '').replace(/\/$/, '')
    const bucket = opts.bucket
    const region = opts.region || 'us-east-1'
    const prefix = (opts.prefix || 'ddrive').replace(/^\/|\/$/g, '')
    const creds = { accessKeyId: opts.accessKeyId, secretAccessKey: opts.secretAccessKey, sessionToken: opts.sessionToken }
    const timeout = opts.timeout || 60000
    const pathStyle = opts.forcePathStyle !== false

    if (!endpoint || !bucket) throw errors.invalidArgument('s3 store requires endpoint and bucket')
    if (!creds.accessKeyId || !creds.secretAccessKey) throw errors.invalidArgument('s3 store requires accessKeyId and secretAccessKey')

    const objectUrl = (key, query) => {
        const url = new URL(endpoint)
        const path = pathStyle ? `/${bucket}/${key}` : `/${key}`
        url.pathname = `${url.pathname.replace(/\/$/, '')}${path.split('/').map((p, i) => (i === 0 ? p : encodeURIComponent(p))).join('/')}`
        if (query) Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v))

        return url.toString()
    }

    const request = async (method, url, { body, headers = {} } = {}) => {
        const signed = sigv4.signRequest({ method, url, headers, body }, creds, { region, service: 's3' })
        const res = await fetch(url, {
            method,
            headers: signed,
            body: method === 'GET' || method === 'HEAD' ? undefined : body,
            signal: AbortSignal.timeout(timeout),
        })
        if (!res.ok) {
            const text = await res.text().catch(() => '')
            const err = errors.internal(`S3 ${method} ${url} failed (${res.status}) ${text.slice(0, 300)}`)
            err.detail = { status: res.status }

            throw err
        }

        return res
    }

    return {
        name: 's3',
        tier: opts.tier || 'ARCHIVE',
        remote: true,
        bucket,
        async init() { return true },
        async put(buffer, meta = {}) {
            const key = `${prefix}/chunks/${crypto.createHash('sha1').update(String(meta.key || '')).digest('hex').slice(0, 8)}/${crypto.randomUUID()}`
            await request('PUT', objectUrl(key), { body: buffer, headers: { 'content-length': String(buffer.length), 'content-type': 'application/octet-stream' } })

            return { locator: `s3://${bucket}/${key}`, size: buffer.length, backend: 's3', tier: this.tier }
        },
        async get(locator, range = {}) {
            const url = new URL(locator)
            const key = `${url.hostname}${url.pathname}`
            const headers = {}
            if (range.start !== undefined || range.end !== undefined) {
                headers.range = `bytes=${range.start ?? 0}-${range.end ?? ''}`
            }
            const res = await request('GET', objectUrl(key.replace(`${bucket}/`, '')), { headers })
            if (!res.body) throw errors.internal('S3 peer returned no body')

            return Readable.fromWeb(res.body)
        },
        async stat(locator) {
            const url = new URL(locator)
            const key = `${url.hostname}${url.pathname}`.replace(`${bucket}/`, '')
            const res = await request('HEAD', objectUrl(key))

            return { size: Number(res.headers.get('content-length') || 0) }
        },
        async delete(locator) {
            const url = new URL(locator)
            const key = `${url.hostname}${url.pathname}`.replace(`${bucket}/`, '')
            await request('DELETE', objectUrl(key))
        },
        async health() {
            try {
                const res = await request('GET', objectUrl('', { 'list-type': '2', 'max-keys': '1' }))

                return { ok: res.ok, backend: 's3', endpoint, bucket, tier: this.tier }
            } catch (err) {
                return { ok: false, backend: 's3', endpoint, bucket, error: err.message }
            }
        },
    }
}

module.exports = { createS3Store }
