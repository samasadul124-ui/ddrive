/**
 * Chunk size limits.
 *
 * A chunk is uploaded to the backend as one blob, and the backends have
 * different ceilings. Discord accepts at most 10 MiB per webhook attachment, so
 * a deployment that used the old 24 MiB default had *every* upload rejected
 * with HTTP 413 - the failure this file pins down.
 *
 * Covered here:
 *   - the default chunk size is the safe value for every backend
 *   - an oversized CHUNK_SIZE is clamped (not ignored, not fatal) for Discord,
 *     including when Discord is only a tier, and recorded for the boot log
 *   - STORAGE_DRIVER=discord without WEBHOOKS fails validation with a helpful
 *     message instead of a stack trace from deep inside the store
 *   - a backend 413 becomes an actionable error naming the fix
 *   - a real upload through the API with the default settings lands in Discord
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { Buffer } = require('node:buffer')

const { loadConfig } = require('../src/config')
const { createHttpServer } = require('../src/http')
const limits = require('../src/lib/limits')

const CHUNK = limits.DISCORD_MAX_CHUNK // what we send
const ATTACHMENT = limits.DISCORD_ATTACHMENT_LIMIT // what Discord accepts per request
const { createDiscordStore } = require('../src/core/storage/discord')
const { createDiscordStub } = require('./fixtures/discord-stub')

const ADMIN = { username: 'admin', password: 'TestPassw0rd!x' }
const WEBHOOKS = 'https://discord.com/api/webhooks/9001/one,https://discord.com/api/webhooks/9002/two'

const configFor = (env = {}) => loadConfig({
    DB_DRIVER: 'sqlite',
    LOG_LEVEL: 'silent',
    STORAGE_DRIVER: 'discord',
    WEBHOOKS,
    ...env,
}, { cwd: os.tmpdir() })

test('the default chunk size is safe for every backend', () => {
    // 10 MiB minus the multipart/encryption allowance: a chunk of exactly 10 MiB
    // would produce a request body larger than Discord accepts
    assert.equal(limits.DISCORD_ATTACHMENT_LIMIT, 10485760)
    assert.equal(limits.DEFAULT_CHUNK_SIZE, CHUNK)
    assert.equal(CHUNK, 10420224)
    assert.ok(CHUNK < ATTACHMENT)

    for (const env of [{ STORAGE_DRIVER: 'discord', WEBHOOKS }, { STORAGE_DRIVER: 'local' }, {}]) {
        const config = configFor(env)
        assert.equal(config.storage.chunkSize, CHUNK, `default wrong for ${JSON.stringify(env)}`)
        assert.equal(config.storage.chunkSizeAdjustment, null, 'a default never needs clamping')
    }
})

test('an oversized CHUNK_SIZE is clamped for discord deployments', () => {
    // the value from the original v4 documentation: bigger than Discord accepts
    const legacy = configFor({ CHUNK_SIZE: '25165824' })
    assert.equal(legacy.storage.requestedChunkSize, 25165824)
    assert.equal(legacy.storage.chunkSize, CHUNK)
    assert.deepEqual(legacy.storage.chunkSizeAdjustment, {
        requested: 25165824, applied: CHUNK, limit: CHUNK, drivers: ['discord'],
    })
    // even exactly 10 MiB is clamped: the request would be bigger than the chunk
    assert.equal(configFor({ CHUNK_SIZE: String(ATTACHMENT) }).storage.chunkSize, CHUNK)
    // while a value at or below the limit is honoured
    assert.equal(configFor({ CHUNK_SIZE: String(CHUNK) }).storage.chunkSize, CHUNK)
    assert.equal(configFor({ CHUNK_SIZE: '8388608' }).storage.chunkSize, 8388608)

    // a discord *tier* counts too
    const tiered = configFor({
        STORAGE_DRIVER: 'local',
        WEBHOOKS: '',
        TIER_COOL_DRIVER: 'discord',
        TIER_COOL_WEBHOOKS: WEBHOOKS.split(',')[0],
        CHUNK_SIZE: '25165824',
    })
    assert.equal(tiered.storage.chunkSize, CHUNK)
    assert.equal(tiered.storage.discordBacked, true)

    // non-discord backends keep the larger ceiling
    const local = configFor({ STORAGE_DRIVER: 'local', WEBHOOKS: '', CHUNK_SIZE: '25165824' })
    assert.equal(local.storage.chunkSize, 25165824)
    assert.equal(local.storage.chunkSizeAdjustment, null)

    // ...but not an unbounded one
    const huge = configFor({ STORAGE_DRIVER: 'local', WEBHOOKS: '', CHUNK_SIZE: '999999999' })
    assert.equal(huge.storage.chunkSize, limits.MAX_CHUNK_SIZE)
})

test('discord storage without webhooks fails fast with an explanation', () => {
    assert.throws(
        () => loadConfig({ STORAGE_DRIVER: 'discord', WEBHOOKS: '', LOG_LEVEL: 'silent' }, { cwd: os.tmpdir(), validate: true }),
        /WEBHOOKS/,
    )
    // a single webhook is enough
    const one = loadConfig({ STORAGE_DRIVER: 'discord', WEBHOOKS: WEBHOOKS.split(',')[0], LOG_LEVEL: 'silent' }, { cwd: os.tmpdir(), validate: true })
    assert.equal(one.storage.webhooks.length, 1)
})

test('a backend rejection of an oversized chunk is actionable', async (t) => {
    // the store allows up to its 10 MiB chunk limit, this backend only 4 KiB, so
    // the *backend* rejects the chunk - the real 413 path
    const stub = await createDiscordStub({ maxAttachmentBytes: 4096 })
    await stub.start()
    t.after(async () => { await stub.stop() })

    const store = createDiscordStore({
        webhooks: [`${stub.base}/webhooks/9001/small`],
        apiBase: stub.base,
    })

    const oversized = Buffer.alloc(8192, 'x')
    await assert.rejects(
        () => store.put(oversized),
        (err) => {
            assert.match(err.message, /413/, err.message)
            assert.match(err.message, new RegExp(`CHUNK_SIZE=${CHUNK}`), 'the error must name the fix')
            assert.equal(err.code, 'InvalidArgument')
            assert.equal(err.statusCode, 400)

            return true
        },
    )

    // the store's own guard also explains itself, without touching the network
    const before = stub.hits('small')
    await assert.rejects(
        () => store.put(Buffer.alloc(CHUNK + 1)),
        new RegExp(`CHUNK_SIZE=${CHUNK}`),
    )
    assert.equal(stub.hits('small'), before, 'a chunk over the store limit must be rejected before uploading')
    assert.equal(stub.hits('small'), 1, 'a too-large chunk must not be retried on every webhook')
})

test('an oversized chunk is rejected by the stub at the real 10 MiB limit', async (t) => {
    const stub = await createDiscordStub()
    await stub.start()
    t.after(async () => { await stub.stop() })
    assert.equal(stub.maxAttachmentBytes, ATTACHMENT)

    const store = createDiscordStore({
        webhooks: [`${stub.base}/webhooks/9001/limit`],
        apiBase: stub.base,
        timeout: 60000,
    })

    // the biggest chunk we ever send is accepted, envelope included
    const atLimit = Buffer.alloc(CHUNK, 'a')
    const stored = await store.put(atLimit)
    assert.equal(stored.size, CHUNK)

    // a chunk of exactly the advertised limit is refused by the store itself
    // (its multipart body would exceed what Discord accepts)
    await assert.rejects(() => store.put(Buffer.alloc(ATTACHMENT, 'a')), new RegExp(`CHUNK_SIZE=${CHUNK}`))
})

test('uploads reach Discord with the default chunk size', async (t) => {
    const stub = await createDiscordStub()
    await stub.start()
    t.after(async () => { await stub.stop() })

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ddrive-chunk-'))
    // deliberately *no* CHUNK_SIZE: the user's situation is "defaults, no tuning"
    const config = loadConfig({
        DB_DRIVER: 'sqlite',
        SQLITE_FILE: path.join(dir, 'ddrive.sqlite'),
        DATA_DIR: path.join(dir, 'data'),
        STORAGE_DRIVER: 'discord',
        WEBHOOKS: `${stub.base}/webhooks/9001/one,${stub.base}/webhooks/9002/two`,
        DISCORD_API_BASE: stub.base,
        MASTER_KEY: 'chunk-size-test-master-key',
        BOOTSTRAP_ADMIN_USER: ADMIN.username,
        BOOTSTRAP_ADMIN_PASSWORD: ADMIN.password,
        PORT: '0',
        HOST: '127.0.0.1',
        LOG_LEVEL: 'silent',
    }, { cwd: dir })
    assert.equal(config.storage.chunkSize, CHUNK)

    const server = createHttpServer(config, { logger: false })
    await server.start()
    t.after(async () => {
        await server.stop().catch(() => {})
        fs.rmSync(dir, { recursive: true, force: true })
    })
    const base = `http://127.0.0.1:${server.fastify.server.address().port}`
    const auth = `Basic ${Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString('base64')}`

    // one full chunk plus a remainder: proves the default size is actually used
    // (a single small file would pass even with a broken chunk size)
    const payloadSize = CHUNK + (512 * 1024)
    const payload = Buffer.alloc(payloadSize, 0)
    for (let i = 0; i < payloadSize; i += 4096) payload.writeUInt32BE(i % 4294967295, i)

    const bucket = await fetch(`${base}/api/buckets`, {
        method: 'POST',
        headers: { authorization: auth, 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'discord-default' }),
    })
    assert.equal(bucket.status, 201, await bucket.text())

    const put = await fetch(`${base}/api/buckets/discord-default/objects/big.bin`, {
        method: 'PUT',
        headers: { authorization: auth, 'content-type': 'application/octet-stream' },
        body: payload,
    })
    assert.equal(put.status, 201, await put.text())

    // every chunk really is on the Discord stub
    assert.ok(stub.attachments.size >= 2, `expected the payload to be split, got ${stub.attachments.size} attachment(s)`)
    const attachmentSizes = [...stub.attachments.values()].map((a) => a.body.length)
    assert.ok(attachmentSizes.every((size) => size <= CHUNK), `oversized chunk uploaded: ${attachmentSizes}`)
    assert.ok(attachmentSizes.includes(CHUNK), `no full-size chunk was uploaded: ${attachmentSizes}`)

    const got = await fetch(`${base}/api/buckets/discord-default/objects/big.bin/download`, { headers: { authorization: auth } })
    assert.equal(got.status, 200)
    const body = Buffer.from(await got.arrayBuffer())
    assert.equal(body.length, payloadSize)
    assert.ok(body.equals(payload), 'the downloaded bytes must match what was uploaded')
})
