/**
 * Discord chunk store.
 *
 * Each chunk is uploaded as an attachment to one of the configured webhook
 * URLs (round robin, batched under the 10 requests/second/channel limit). This
 * is the original DDrive 4.x storage backend, refactored behind the ChunkStore
 * interface so it can be combined with tiering, replication and versioning.
 */
const http = require('http')
const https = require('https')
const { randomUUID } = require('crypto')
const { errors } = require('../../lib/errors')
const { sleep } = require('../../lib/util')

const MAX_ATTACHMENT = 26109542 // hard Discord limit (slightly under 25 MiB)

const createDiscordStore = (opts = {}) => {
    // Normalise each entry to a full URL. Discord URLs are rewritten onto
    // `apiBase` (so a different REST base can be configured); any other
    // absolute URL - a self-hosted webhook proxy, a test double - is used as
    // given.
    const webhooks = (opts.webhooks || [])
        .map((url) => String(url).trim())
        .filter(Boolean)
        .map((url) => {
            const stripped = url.replace(/^https:\/\/(discord|discordapp)\.com\/api(\/v\d+)?/, '')
            if (stripped !== url) return String(opts.apiBase || 'https://discord.com/api').replace(/\/+$/, '') + stripped
            if (/^https?:\/\//.test(url)) return url.replace(/\/+$/, '')

            return `${String(opts.apiBase || 'https://discord.com/api').replace(/\/+$/, '')}/${url.replace(/^\/+/, '')}`
        })
    if (!webhooks.length) throw errors.invalidArgument('discord chunk store requires at least one webhook URL')

    const timeout = opts.timeout || 60000
    const concurrency = Math.max(1, opts.concurrency || webhooks.length)
    let cursor = 0
    const nextWebhook = () => {
        const url = webhooks[cursor]
        cursor = (cursor + 1) % webhooks.length

        return url
    }

    const upload = async (buffer, filename) => {
        const form = new FormData()
        form.append('file', new Blob([buffer]), filename)
        let lastError
        // Every webhook gets a chance before giving up: one rate limited or
        // revoked webhook must not take the whole deployment down.
        for (let attempt = 0; attempt < webhooks.length; attempt += 1) {
            const webhookUrl = nextWebhook()
            try {
                const res = await fetch(`${webhookUrl}?wait=true`, {
                    method: 'POST',
                    body: form,
                    signal: AbortSignal.timeout(timeout),
                })
                if (res.status === 429) {
                    const body = await res.json().catch(() => ({}))
                    await sleep(Math.ceil((body.retry_after || 1) * 1000))
                    throw errors.tooManyRequests('Discord rate limit')
                }
                if (!res.ok) {
                    const text = await res.text().catch(() => '')
                    throw errors.internal(`Discord webhook upload failed (${res.status}) ${text.slice(0, 200)}`)
                }
                const json = await res.json()
                const attachment = (json.attachments || [])[0]
                if (!attachment) throw errors.internal('Discord webhook response did not include an attachment')

                return attachment
            } catch (err) {
                lastError = err
            }
        }
        throw lastError || errors.internal('Discord upload failed')
    }

    return {
        name: 'discord',
        tier: opts.tier || 'HOT',
        maxChunkSize: MAX_ATTACHMENT,
        concurrency,
        async init() { return true },
        async put(buffer) {
            if (buffer.length > MAX_ATTACHMENT) {
                throw errors.invalidArgument(`chunk of ${buffer.length} bytes exceeds Discord limit of ${MAX_ATTACHMENT}`)
            }
            const attachment = await upload(buffer, randomUUID())

            return {
                locator: attachment.url,
                size: attachment.size || buffer.length,
                backend: 'discord',
                tier: this.tier,
                messageId: attachment.id,
            }
        },
        async get(locator, range = {}) {
            const headers = {}
            if (range.start !== undefined || range.end !== undefined) {
                headers.Range = `bytes=${range.start ?? 0}-${range.end ?? ''}`
            }

            const transport = String(locator).startsWith('http://') ? http : https

            return new Promise((resolve, reject) => {
                const req = transport.get(locator, { headers }, (res) => {
                    if (res.statusCode >= 400) {
                        reject(errors.internal(`Discord CDN returned ${res.statusCode}`))

                        return
                    }
                    resolve(res)
                })
                req.setTimeout(timeout, () => {
                    req.destroy(errors.internal('Discord CDN request timed out'))
                })
                req.on('error', reject)
            })
        },
        async delete() {
            // Discord attachments are cached on the CDN; DDrive removes the
            // metadata and lets Discord garbage collect the CDN copy. Deleting
            // the message would require a bot token, which 4.x deliberately
            // moved away from.
            return true
        },
        async health() {
            try {
                const webhookUrl = webhooks[0]
                const res = await fetch(webhookUrl, { signal: AbortSignal.timeout(10000) })

                return { ok: res.status < 500, backend: 'discord', webhooks: webhooks.length, status: res.status }
            } catch (err) {
                return { ok: false, backend: 'discord', error: err.message }
            }
        },
    }
}

module.exports = { createDiscordStore, MAX_ATTACHMENT }
