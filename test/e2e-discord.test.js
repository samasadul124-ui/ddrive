/**
 * End to end test over a *real HTTP listener* with the Discord chunk backend.
 *
 * The Discord REST/CDN is a local double (test/fixtures/discord-stub.js) - the
 * sandbox has no outbound access to discord.com - but everything else is the
 * production path: Fastify listener, Basic auth, S3 SigV4 auth, WebDAV, the
 * object core, encryption per chunk and the Discord store over real HTTP.
 *
 * Point WEBHOOKS at real Discord webhooks (and drop DISCORD_API_BASE) to run
 * the exact same flow against Discord.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { Buffer } = require('node:buffer')

const { loadConfig } = require('../src/config')
const { createHttpServer } = require('../src/http')
const sigv4 = require('../src/lib/sigv4')
const { createDiscordStub } = require('./fixtures/discord-stub')

const ADMIN = { username: 'admin', password: 'TestPassw0rd!x' }
const WEBHOOK_PATHS = ['webhooks/9001/one', 'webhooks/9002/two', 'webhooks/9003/three']

const boot = async (stub, extraEnv = {}) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ddrive-e2e-'))
    const config = loadConfig({
        DB_DRIVER: 'sqlite',
        SQLITE_FILE: path.join(dir, 'ddrive.sqlite'),
        DATA_DIR: path.join(dir, 'data'),
        STORAGE_DRIVER: 'discord',
        WEBHOOKS: WEBHOOK_PATHS.map((p) => `${stub.base}/${p}`).join(','),
        DISCORD_API_BASE: stub.base,
        CHUNK_SIZE: '1048576',
        MASTER_KEY: 'e2e-master-key',
        BOOTSTRAP_ADMIN_USER: ADMIN.username,
        BOOTSTRAP_ADMIN_PASSWORD: ADMIN.password,
        PORT: '0',
        HOST: '127.0.0.1',
        LOG_LEVEL: 'silent',
        ...extraEnv,
    }, { cwd: dir })
    const server = createHttpServer(config, { logger: false })
    await server.start()
    const base = `http://127.0.0.1:${server.fastify.server.address().port}`

    const stop = async () => {
        await server.stop().catch(() => {})
        fs.rmSync(dir, { recursive: true, force: true })
    }

    return { dir, base, server, stop }
}

const basic = () => `Basic ${Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString('base64')}`

test('S3, REST and WebDAV all round-trip through the Discord backend', async (t) => {
    const stub = await createDiscordStub()
    await stub.start()
    const app = await boot(stub)
    t.after(async () => {
        await app.stop()
        await stub.stop()
    })

    // ---------------------------------------------------------------- setup
    const keyRes = await fetch(`${app.base}/api/admin/access-keys`, {
        method: 'POST',
        headers: { authorization: basic(), 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'admin', description: 'e2e' }),
    })
    assert.equal(keyRes.status, 201)
    const credentials = await keyRes.json()

    const { host } = new URL(app.base)
    const s3 = (method, target, payload = Buffer.alloc(0), headers = {}) => {
        const hash = require('crypto').createHash('sha256').update(payload).digest('hex')
        const signed = sigv4.signRequest({
            method,
            url: `${app.base}/s3${target}`,
            headers: { host, ...headers },
            payloadHash: hash,
        }, { ...credentials, region: 'us-east-1', service: 's3' })

        return fetch(`${app.base}/s3${target}`, { method, headers: signed, body: payload.length ? payload : undefined })
    }

    // ------------------------------------------------------------------- S3
    assert.equal((await s3('PUT', '/e2e-bucket')).status, 200)

    const payload = Buffer.alloc(2 * 1024 * 1024 + 13)
    payload.fill('q')
    const put = await s3('PUT', '/e2e-bucket/discord/big.bin', payload, { 'content-type': 'application/octet-stream' })
    assert.equal(put.status, 200)

    // 3 chunks -> 3 webhook uploads, all served by the stub's CDN
    assert.equal(stub.attachments.size, 3)
    const get = await s3('GET', '/e2e-bucket/discord/big.bin')
    assert.equal(get.status, 200)
    const downloaded = Buffer.from(await get.arrayBuffer())
    assert.equal(downloaded.length, payload.length)
    assert.ok(downloaded.equals(payload), 'S3 download must match the uploaded bytes')

    const ranged = await s3('GET', '/e2e-bucket/discord/big.bin', Buffer.alloc(0), { range: 'bytes=1048570-1048580' })
    assert.equal(ranged.status, 206)
    assert.equal(Buffer.from(await ranged.arrayBuffer()).toString(), 'qqqqqqqqqqq')

    // encryption is applied per chunk before the webhook upload
    const { version } = await app.server.context.objects.getVersion(
        await app.server.context.buckets.get('e2e-bucket'), 'discord/big.bin',
    )
    const blocks = await app.server.context.objects.blocksOf(version.id)
    assert.equal(blocks.length, 3)
    blocks.forEach((block) => {
        assert.match(block.url, /\/attachments\//)
        assert.ok(block.iv && block.wrappedDek, 'each chunk carries its own IV and wrapped DEK')
        // the stored bytes are ciphertext, not the plaintext we uploaded
        const stored = stub.attachments.get(block.url.split('/attachments/')[1].split('/')[0])
        assert.ok(stored && !stored.body.equals(payload.subarray(0, stored.body.length)))
    })

    // ----------------------------------------------------------------- REST
    const restPut = await fetch(`${app.base}/api/buckets/e2e-bucket/objects/rest/note.txt`, {
        method: 'PUT',
        headers: { authorization: basic(), 'content-type': 'text/plain' },
        body: 'rest through discord',
    })
    assert.equal(restPut.status, 201)

    const restGet = await fetch(`${app.base}/api/buckets/e2e-bucket/objects/rest/note.txt/download`, {
        headers: { authorization: basic() },
    })
    assert.equal(restGet.status, 200)
    assert.equal(await restGet.text(), 'rest through discord')

    // --------------------------------------------------------------- WebDAV
    const mkcol = await fetch(`${app.base}/webdav/e2e-bucket/dav-dir/`, { method: 'MKCOL', headers: { authorization: basic() } })
    assert.equal(mkcol.status, 201)

    const davPut = await fetch(`${app.base}/webdav/e2e-bucket/dav-dir/file.txt`, {
        method: 'PUT',
        headers: { authorization: basic(), 'content-type': 'text/plain' },
        body: 'webdav through discord',
    })
    assert.equal(davPut.status, 201)

    const davGet = await fetch(`${app.base}/webdav/e2e-bucket/dav-dir/file.txt`, { headers: { authorization: basic() } })
    assert.equal(davGet.status, 200)
    assert.equal(await davGet.text(), 'webdav through discord')

    const propfind = await fetch(`${app.base}/webdav/e2e-bucket/dav-dir/`, {
        method: 'PROPFIND',
        headers: { authorization: basic(), depth: '1', 'content-type': 'text/xml' },
        body: '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>',
    })
    assert.equal(propfind.status, 207)
    assert.match(await propfind.text(), /file\.txt/)

    // ------------------------------------------------- every chunk on Discord
    const objects = app.server.context.objects
    const bucket = await app.server.context.buckets.get('e2e-bucket')
    for (const key of ['rest/note.txt', 'dav-dir/file.txt']) {
        const { version } = await objects.getVersion(bucket, key)
        const rows = await objects.blocksOf(version.id)
        assert.ok(rows.length >= 1)
        rows.forEach((row) => assert.match(row.url, /\/attachments\//))
    }
    const localChunks = path.join(app.dir, 'data', 'chunks')
    const files = fs.existsSync(localChunks) ? fs.readdirSync(localChunks) : []
    assert.deepEqual(files, [], 'nothing may fall back to the local disk')
})

test('a revoked webhook does not take the deployment down (failover)', async (t) => {
    const stub = await createDiscordStub()
    await stub.start()
    const app = await boot(stub)
    t.after(async () => {
        await app.stop()
        await stub.stop()
    })

    // a fresh deployment: create the bucket first
    const created = await fetch(`${app.base}/api/buckets`, {
        method: 'POST',
        headers: { authorization: basic(), 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'e2e-bucket' }),
    })
    assert.equal(created.status, 201)

    // the first two webhooks are revoked, only the third accepts uploads
    stub.fail('one', 401)
    stub.fail('two', 429, 0.02)

    const res = await fetch(`${app.base}/api/buckets/e2e-bucket/objects/failover.txt`, {
        method: 'PUT',
        headers: { authorization: basic(), 'content-type': 'text/plain' },
        body: 'survives a revoked webhook',
    })
    assert.equal(res.status, 201)

    const back = await fetch(`${app.base}/api/buckets/e2e-bucket/objects/failover.txt/download`, { headers: { authorization: basic() } })
    assert.equal(back.status, 200)
    assert.equal(await back.text(), 'survives a revoked webhook')

    assert.ok(stub.hits('one') > 0, 'the revoked webhook was tried')
    assert.ok(stub.hits('two') > 0, 'the rate limited webhook was tried')
    assert.ok(stub.hits('three') > 0, 'the healthy webhook served the chunk')
})
