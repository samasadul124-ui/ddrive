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
 * a bare `node scripts/discord-live-check.js` picks them up. Pass --size N to
 * test a custom payload size (default 3 MiB, i.e. several chunks at the
 * default 24 MiB chunk size it stays one chunk - set CHUNK_SIZE to force more).
 */
const crypto = require('crypto')
const path = require('path')

require('dotenv').config({ path: path.join(__dirname, '..', 'config', '.env') })

const { createChunkStore } = require('../src/core/storage')
const { loadConfig } = require('../src/config')

const args = process.argv.slice(2)
const sizeArg = args.indexOf('--size')
const SIZE = sizeArg >= 0 ? Number(args[sizeArg + 1]) : 3 * 1024 * 1024

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
    console.log(`webhooks: ${webhooks.length} (${webhooks.map(redact).join(', ')})`)

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

    await store.delete(stored.locator)
    check('delete is a safe no-op (the CDN keeps the attachment)', true)
    console.log('\nAll checks passed. Remember to delete the test attachments from the channel.')
}

main().catch((err) => {
    console.error(`error: ${err.message}`)
    process.exit(1)
})
