#!/usr/bin/env node
/**
 * Live check of the Discord chunk backend against *real* webhooks.
 *
 * The sandboxed CI environment has no outbound access to discord.com, so run
 * this where Discord is reachable:
 *
 *   WEBHOOKS="https://discord.com/api/webhooks/.../...,https://discord.com/api/webhooks/.../..." \
 *     node scripts/discord-live-check.js
 *
 * If you keep the URLs in config/.env (WEBHOOKS=..., STORAGE_DRIVER=discord)
 * a bare `node scripts/discord-live-check.js` picks them up.
 *
 *   --size N    payload to round-trip (default 3 MiB)
 *   --chunks    also try one chunk of exactly the configured chunk size, which
 *               is what a real upload sends (catches a CHUNK_SIZE that Discord
 *               rejects with HTTP 413)
 *
 * It reports the effective chunk size first, so a "nothing uploads" report can
 * be traced to the size limit immediately.
 */
const crypto = require('crypto')
const path = require('path')

require('dotenv').config({ path: path.join(__dirname, '..', 'config', '.env') })

const { createChunkStore } = require('../src/core/storage')
const { loadConfig } = require('../src/config')

const args = process.argv.slice(2)
const sizeArg = args.indexOf('--size')
const SIZE = sizeArg >= 0 ? Number(args[sizeArg + 1]) : 3 * 1024 * 1024
const CHECK_CHUNK = args.includes('--chunks')

const config = loadConfig({ ...process.env, DATA_DIR: process.env.DATA_DIR || path.join(__dirname, '..', 'data') })
const webhooks = config.storage.webhooks
if (!webhooks.length) {
    console.error('No webhooks configured. Set WEBHOOKS="url1,url2" (comma separated) or put them in config/.env.')
    process.exit(2)
}

const redact = (url) => url.replace(/(webhooks\/\d+\/)[\w-]+/, '$1***')
const check = (label, ok, extra = '') => {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ` ${extra}` : ''}`)
    if (!ok) process.exitCode = 1
}

const main = async () => {
    const { DISCORD_ATTACHMENT_LIMIT, humanBytes } = require('../src/lib/limits')
    console.log(`webhooks: ${webhooks.length} (${webhooks.map(redact).join(', ')})`)
    console.log(`chunk size: ${humanBytes(config.storage.chunkSize)} (Discord accepts at most ${humanBytes(DISCORD_ATTACHMENT_LIMIT)} per request)`)
    if (config.storage.chunkSizeAdjustment) {
        const adj = config.storage.chunkSizeAdjustment
        console.log(`note: CHUNK_SIZE=${adj.requested} was clamped to ${humanBytes(adj.applied)}; `
            + 'discord rejects a larger attachment with HTTP 413')
    }

    const store = createChunkStore({
        driver: 'discord',
        discord: {
            webhooks,
            apiBase: config.storage.discordApiBase,
            timeout: config.servers.requestTimeout,
            concurrency: config.storage.concurrency,
        },
    })

    const health = await store.health()
    check('webhook reachable', health.HOT && health.HOT.ok === true, JSON.stringify(health.HOT))

    const payload = crypto.randomBytes(SIZE)
    const putStarted = Date.now()
    const stored = await store.put(payload)
    console.log(`uploaded ${payload.length} bytes in ${Date.now() - putStarted} ms -> ${stored.locator}`)

    const stream = await store.get(stored.locator)
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)
    const readBack = Buffer.concat(chunks)
    check('download matches upload', readBack.length === payload.length && readBack.equals(payload), `${readBack.length} bytes`)

    const ranged = await store.get(stored.locator, { start: 10, end: 41 })
    const rangedChunks = []
    for await (const chunk of ranged) rangedChunks.push(chunk)
    const slice = Buffer.concat(rangedChunks)
    check('ranged read', slice.equals(payload.subarray(10, 42)), `${slice.length} bytes`)

    if (CHECK_CHUNK) {
        // exactly what a real upload sends: one full chunk
        const chunk = crypto.randomBytes(config.storage.chunkSize)
        try {
            const put = Date.now()
            const chunkStored = await store.put(chunk)
            check(`a full ${humanBytes(chunk.length)} chunk is accepted`, true, `${Date.now() - put} ms`)
            await store.delete(chunkStored.locator)
        } catch (err) {
            check(`a full ${humanBytes(chunk.length)} chunk is accepted`, false, err.message)
        }
    }

    await store.delete(stored.locator)
    check('delete is a safe no-op (the CDN keeps the attachment)', true)
    console.log('\nAll checks passed. Remember to delete the test attachments from the channel.')
}

main().catch((err) => {
    console.error(`error: ${err.message}`)
    process.exit(1)
})
