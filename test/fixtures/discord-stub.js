/**
 * Minimal Discord REST/CDN look-alike used by the test suite.
 *
 * Implements the two endpoints the chunk store talks to:
 *   POST /webhooks/:id/:token?wait=true   multipart upload -> attachment JSON
 *   GET  /attachments/:id/:name           CDN download, supports Range
 *
 * It also lets a test script flakiness: a webhook that returns 429 (with
 * `retry_after`), one that returns 500, or one that is revoked (401).
 */
const http = require('http')
const { randomUUID } = require('crypto')

/**
 * Pull the first `file` part out of a multipart/form-data body - enough of a
 * parser to stand in for Discord's upload endpoint.
 */
const extractFile = (contentType, raw) => {
    const boundary = /boundary=([^;]+)/i.exec(contentType)
    if (!boundary) return null
    const delimiter = Buffer.from(`--${boundary[1].replace(/^"|"$/g, '')}`)
    const parts = []
    let index = raw.indexOf(delimiter)
    while (index !== -1) {
        const next = raw.indexOf(delimiter, index + delimiter.length)
        if (next === -1) break
        parts.push(raw.subarray(index + delimiter.length, next))
        index = next
    }
    for (const part of parts) {
        const headerEnd = part.indexOf('\r\n\r\n')
        if (headerEnd < 0) continue
        const headers = part.subarray(0, headerEnd).toString('utf8')
        if (!/name="file"/i.test(headers)) continue
        const filename = /filename="([^"]*)"/i.exec(headers)

        return { filename: filename ? filename[1] : null, data: part.subarray(headerEnd + 4).subarray(0, part.length - headerEnd - 4 - 2) }
    }

    return null
}

const createDiscordStub = (opts = {}) => {
    /** id -> { name, type, body, chunks: [buffer] } */
    const attachments = new Map()
    /** webhook token -> { status, retryAfter, hits } */
    const webhooks = new Map()
    const calls = []

    const webhook = (token) => {
        if (!webhooks.has(token)) webhooks.set(token, { status: 200, retryAfter: 0, hits: 0 })
        return webhooks.get(token)
    }

    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://127.0.0.1')
        // derive the port from the socket so the stub also works when it is
        // started with `server.listen()` directly
        const origin = `http://127.0.0.1:${req.socket.localPort}`
        calls.push({ method: req.method, path: url.pathname, query: url.search })

        // ---- webhook upload
        const upload = /^\/webhooks\/(\d+)\/([^/]+)$/.exec(url.pathname)
        if (upload && req.method === 'POST') {
            const state = webhook(upload[2])
            state.hits += 1

            const chunks = []
            req.on('data', (chunk) => chunks.push(chunk))
            req.on('end', () => {
                if (state.status !== 200) {
                    res.writeHead(state.status, { 'content-type': 'application/json' })
                    res.end(JSON.stringify(state.status === 429
                        ? { message: 'You are being rate limited.', retry_after: state.retryAfter || 0.1, global: false }
                        : { message: 'stub failure', code: 500 }))

                    return
                }

                const raw = Buffer.concat(chunks)
                const file = extractFile(req.headers['content-type'] || '', raw)
                if (!file) {
                    res.writeHead(400, { 'content-type': 'application/json' })
                    res.end(JSON.stringify({ message: 'Expected a multipart file part' }))

                    return
                }
                const id = randomUUID()
                const name = file.filename || 'attachment.bin'
                attachments.set(id, { id, name, body: file.data })
                const body = file.data

                res.writeHead(200, { 'content-type': 'application/json' })
                res.end(JSON.stringify({
                    id: randomUUID(),
                    type: 0,
                    channel_id: upload[1],
                    attachments: [{
                        id, filename: name, size: body.length, url: `${origin}/attachments/${id}/${name}`,
                        content_type: 'application/octet-stream',
                    }],
                }))
            })

            return
        }

        // ---- CDN download
        const download = /^\/attachments\/([^/]+)\/(.+)$/.exec(url.pathname)
        if (download && req.method === 'GET') {
            const attachment = attachments.get(download[1])
            if (!attachment) {
                res.writeHead(404).end('not found')

                return
            }
            const { body } = attachment
            const range = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '')
            if (range) {
                const start = range[1] ? Number(range[1]) : 0
                const end = range[2] ? Number(range[2]) : body.length - 1
                const slice = body.subarray(start, Math.min(end, body.length - 1) + 1)
                res.writeHead(206, {
                    'content-type': 'application/octet-stream',
                    'content-length': slice.length,
                    'content-range': `bytes ${start}-${start + slice.length - 1}/${body.length}`,
                })
                res.end(slice)

                return
            }
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': body.length })
            res.end(body)

            return
        }

        // ---- health probe (webhook lookup)
        if (upload && req.method === 'GET') {
            const state = webhook(upload[2])
            res.writeHead(state.status === 200 ? 200 : state.status, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ id: upload[1], token: upload[2], name: 'stub' }))

            return
        }

        res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ message: 'Unknown endpoint' }))
    })

    let port = 0

    return {
        server,
        calls,
        attachments,
        /** Make a webhook token fail with a HTTP status (429/500/401/...). */
        fail(token, status, retryAfter = 0.05) {
            const state = webhook(token)
            state.status = status
            state.retryAfter = retryAfter
        },
        heal(token) { webhook(token).status = 200 },
        hits(token) { return webhook(token).hits },
        async start() {
            await new Promise((resolve) => { server.listen(0, '127.0.0.1', resolve) })
            port = server.address().port

            return port
        },
        async stop() { await new Promise((resolve) => server.close(resolve)) },
        get base() { return `http://127.0.0.1:${port || (server.address() && server.address().port)}` },
    }
}

module.exports = { createDiscordStub }
