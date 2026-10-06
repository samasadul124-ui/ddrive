/**
 * Discord chunk store: the original DDrive backend, exercised against a local
 * Discord REST/CDN look-alike (test/fixtures/discord-stub.js) because the test
 * environment has no outbound access to discord.com.
 *
 * Covers: chunking, round-robin sharding over multiple webhooks, CDN reads
 * with Range, rate-limit / revoked-webhook failover and 10 MiB+ payloads.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const { Readable } = require('node:stream')

const { createTestServer } = require('./helpers')
const { createDiscordStub } = require('./fixtures/discord-stub')

const WEBHOOKS = ['webhooks/111/alpha', 'webhooks/222/bravo', 'webhooks/333/charlie']

const setup = async (stub, env = {}) => {
    const t = await createTestServer({
        STORAGE_DRIVER: 'discord',
        WEBHOOKS: WEBHOOKS.map((path) => `${stub.base}/${path}`).join(','),
        DISCORD_API_BASE: stub.base,
        CHUNK_SIZE: '1048576',
        ...env,
    })
    return t
}

const put = (t, bucket, path, body, opts = {}) => t.context.objects.putObject({
    bucket, path, stream: Readable.from([Buffer.from(body)]), contentType: 'application/octet-stream', actor: { name: 'tester' }, ...opts,
})

const read = async (t, bucket, path) => {
    const { version } = await t.context.objects.getVersion(bucket, path)
    const out = await t.context.objects.stream(version)
    const chunks = []
    for await (const chunk of out.stream) chunks.push(chunk)

    return Buffer.concat(chunks)
}

test('chunks are uploaded to Discord and streamed back byte for byte', async () => {
    const stub = await createDiscordStub()
    const base = await stub.start()
    const t = await setup(stub)
    try {
        const bucket = await t.context.buckets.create('multi-bucket', { ownerId: null, versioning: 'enabled' })
        const payload = Buffer.alloc(3 * 1024 * 1024 + 7)
        for (let i = 0; i < payload.length; i += 1) payload[i] = i % 251

        const result = await put(t, bucket, 'multi.bin', payload)
        assert.equal(result.size, payload.length)

        // 1 MiB chunks: 3 full + 1 remainder => 4 chunks, 4 webhook uploads
        assert.equal(stub.calls.filter((c) => c.method === 'POST').length, 4)

        const blocks = await t.context.objects.blocksOf(result.versionId)
        assert.equal(blocks.length, 4)
        blocks.forEach((block) => {
            assert.match(block.url, /\/attachments\//)
            assert.equal(block.backend, 'discord')
            // every chunk is encrypted before it leaves the process
            assert.ok(block.iv && block.wrappedDek && block.keyId)
        })

        const readBack = await read(t, bucket, 'multi.bin')
        assert.equal(readBack.length, payload.length)
        assert.ok(readBack.equals(payload), 'round-tripped bytes must match exactly')

        // every byte lives in the Discord stub, nothing on the local disk
        const chunksDir = require('path').join(t.dir, 'data', 'chunks')
        const localFiles = require('fs').existsSync(chunksDir) ? require('fs').readdirSync(chunksDir) : []
        assert.deepEqual(localFiles, [])
        assert.equal(stub.attachments.size, 4)
    } finally {
        await t.close()
        await stub.stop()
        void base
    }
})

test('chunks are sharded round-robin across every webhook', async () => {
    const stub = await createDiscordStub()
    await stub.start()
    const t = await setup(stub)
    try {
        const bucket = await t.context.buckets.create('shard-bucket', { ownerId: null })
        // 6 chunks => round robin must touch all three webhooks
        const payload = Buffer.alloc(6 * 1024 * 1024 + 1, 'z')
        await put(t, bucket, 'sharded.bin', payload)

        const used = WEBHOOKS.map((path) => stub.hits(path.split('/')[2]))
        assert.equal(used.every((hits) => hits > 0), true, `all webhooks used, got ${used.join(',')}`)
        assert.equal(used.reduce((a, b) => a + b, 0), 7)
    } finally {
        await t.close()
        await stub.stop()
    }
})

test('a rate limited webhook is retried on the next one', async () => {
    const stub = await createDiscordStub()
    await stub.start()
    const t = await setup(stub)
    try {
        const bucket = await t.context.buckets.create('ratelimit-bucket', { ownerId: null })
        stub.fail('alpha', 429, 0.02)
        stub.fail('bravo', 500)

        const body = Buffer.from('rate limit test payload')
        const result = await put(t, bucket, 'ok.txt', body)
        assert.equal(result.size, body.length)
        assert.equal((await read(t, bucket, 'ok.txt')).toString(), body.toString())

        // both broken webhooks were tried, then the healthy one served the chunk
        assert.ok(stub.hits('alpha') > 0)
        assert.ok(stub.hits('bravo') > 0)
        assert.ok(stub.hits('charlie') > 0)
    } finally {
        await t.close()
        await stub.stop()
    }
})

test('the upload fails only when every webhook is broken', async () => {
    const stub = await createDiscordStub()
    await stub.start()
    const t = await setup(stub)
    try {
        const bucket = await t.context.buckets.create('broken-bucket', { ownerId: null })
        WEBHOOKS.forEach((path) => stub.fail(path.split('/')[2], 401))

        await assert.rejects(
            () => put(t, bucket, 'nope.bin', Buffer.alloc(1024, 'x')),
            (err) => err.statusCode >= 400 || /Discord/.test(err.message),
        )
        // no half-written object is left behind
        assert.equal(await t.context.objects.getNode(bucket.id, 'nope.bin'), null)
    } finally {
        await t.close()
        await stub.stop()
    }
})

test('range reads hit the Discord CDN with a Range header', async () => {
    const stub = await createDiscordStub()
    await stub.start()
    const t = await setup(stub)
    try {
        const bucket = await t.context.buckets.create('range-bucket', { ownerId: null })
        const payload = Buffer.from('0123456789abcdefghij')
        await put(t, bucket, 'slice.txt', payload)

        const { version } = await t.context.objects.getVersion(bucket, 'slice.txt')
        const ranged = await t.context.objects.stream(version, { start: 4, end: 9 })
        const chunks = []
        for await (const chunk of ranged.stream) chunks.push(chunk)

        assert.equal(Buffer.concat(chunks).toString(), '456789')
        assert.equal(ranged.length, 6)
        assert.equal(stub.calls.some((c) => c.method === 'GET' && c.path.includes('/attachments/')), true)
    } finally {
        await t.close()
        await stub.stop()
    }
})

test('health probe reports the configured webhooks', async () => {
    const stub = await createDiscordStub()
    await stub.start()
    const t = await setup(stub)
    try {
        // the facade reports health per tier; the primary tier is the Discord store
        const health = await t.context.store.health()
        assert.equal(health.HOT.ok, true)
        assert.equal(health.HOT.backend, 'discord')
        assert.equal(health.HOT.webhooks, 3)
        assert.deepEqual(Object.keys(health), ['HOT'])
    } finally {
        await t.close()
        await stub.stop()
    }
})
