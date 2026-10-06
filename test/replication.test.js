/**
 * Multi-AZ replication between two live nodes.
 *
 * Two independent DDrive instances are started on real ports (each with its own
 * SQLite database and data directory) and peer A is pointed at peer B. Objects,
 * deletes and metadata changes must arrive on B, and the replication endpoint
 * must reject anything that is not correctly signed.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { Buffer } = require('node:buffer')

const { loadConfig } = require('../src/config')
const { createHttpServer } = require('../src/http')
const util = require('../src/lib/util')

const ADMIN = { username: 'admin', password: 'TestPassw0rd!x' }
const PEER_SECRET = 'replication-peer-secret'

/** Boot a standalone node on a random port. */
const bootNode = async (name, region) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `ddrive-${name}-`))
    const config = loadConfig({
        DB_DRIVER: 'sqlite',
        SQLITE_FILE: path.join(dir, 'ddrive.sqlite'),
        DATA_DIR: path.join(dir, 'data'),
        STORAGE_DRIVER: 'local',
        MASTER_KEY: 'replication-test-master-key',
        SECRET: 'replication-test-legacy-secret',
        BOOTSTRAP_ADMIN_USER: ADMIN.username,
        BOOTSTRAP_ADMIN_PASSWORD: ADMIN.password,
        PORT: '0',
        HOST: '127.0.0.1',
        NODE_NAME: name,
        NODE_REGION: region,
        LOG_LEVEL: 'silent',
    }, { cwd: dir })
    const server = createHttpServer(config, { logger: false })
    await server.start()
    const base = `http://127.0.0.1:${server.fastify.server.address().port}`

    const auth = `Basic ${Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString('base64')}`
    const api = async (method, url, body) => {
        const res = await fetch(`${base}${url}`, {
            method,
            headers: { authorization: auth, 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
        })

        return { status: res.status, body: await res.json().catch(() => null) }
    }
    const put = (bucket, key, content) => fetch(`${base}/api/buckets/${bucket}/objects/${key}`, {
        method: 'PUT',
        headers: { authorization: auth, 'content-type': 'text/plain' },
        body: content,
    })
    const get = async (bucket, key) => {
        const res = await fetch(`${base}/api/buckets/${bucket}/objects/${key}/download`, { headers: { authorization: auth } })

        return { status: res.status, text: res.status === 200 ? await res.text() : null }
    }

    const stop = async () => {
        await server.stop().catch(() => {})
        fs.rmSync(dir, { recursive: true, force: true })
    }

    return {
        name, region, dir, base, server, api, put, get, stop, context: server.context,
    }
}

/** Wait until `check()` is truthy, or fail after `timeoutMs`. */
const waitFor = async (check, timeoutMs = 15000, label = 'condition') => {
    const deadline = Date.now() + timeoutMs
    let last
    while (Date.now() < deadline) {
        // eslint-disable-next-line no-await-in-loop
        last = await check()
        if (last) return last
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => { setTimeout(resolve, 100) })
    }
    throw new Error(`timed out waiting for ${label}`)
}

/** Link A -> B (outbound on A, inbound on B) and return the peer. */
const link = async (a, b, opts = {}) => {
    const created = await a.api('POST', '/api/admin/replication', {
        name: 'az2-link',
        endpoint: b.base,
        region: b.region,
        bucket: 'replica-bucket',
        accessKeyId: 'repl-key',
        secret: PEER_SECRET,
        direction: 'outbound',
        ...opts,
    })
    assert.equal(created.status, 201, JSON.stringify(created.body))

    // B must know the same peer name + secret to accept the signed pushes
    await b.api('POST', '/api/admin/replication', {
        name: 'az2-link',
        endpoint: a.base,
        region: a.region,
        bucket: 'replica-bucket',
        accessKeyId: 'repl-key',
        secret: PEER_SECRET,
        direction: 'inbound',
    })

    return created.body
}

test('objects, metadata and deletes replicate to a peer node', async (t) => {
    const a = await bootNode('node-a', 'az1')
    const b = await bootNode('node-b', 'az2')
    t.after(async () => {
        await a.stop()
        await b.stop()
    })

    await link(a, b)

    // both nodes need the bucket; the peer creates it on first inbound object
    assert.equal((await a.api('POST', '/api/buckets', { name: 'replica-bucket', versioning: 'enabled' })).status, 201)

    const health = await a.api('POST', '/api/admin/replication/az2-link/test')
    assert.equal(health.body.ok, true, JSON.stringify(health.body))

    // ---- an object written on A appears on B
    assert.equal((await a.put('replica-bucket', 'replicated.txt', 'hello from az1')).status, 201)
    const arrived = await waitFor(async () => {
        const res = await b.get('replica-bucket', 'replicated.txt')

        return res.status === 200 ? res.text : null
    }, 20000, 'object to replicate')
    assert.equal(arrived, 'hello from az1')

    // the receiving node created the bucket itself
    const targetBucket = await b.context.buckets.get('replica-bucket')
    assert.ok(targetBucket)

    // the object is not a hollow copy: it can be read back through the core too
    const { version } = await b.context.objects.getVersion(targetBucket, 'replicated.txt')
    const blocks = await b.context.objects.blocksOf(version.id)
    assert.ok(blocks.length >= 1, 'the replica must have stored chunks')

    // ---- a second write replaces the replica
    assert.equal((await a.put('replica-bucket', 'replicated.txt', 'second revision')).status, 201)
    const updated = await waitFor(async () => {
        const res = await b.get('replica-bucket', 'replicated.txt')

        return res.text === 'second revision' ? res.text : null
    }, 20000, 'updated object to replicate')
    assert.equal(updated, 'second revision')

    // ---- a permanent delete propagates (the old bug: the task could not
    //      resolve its source row and stayed pending forever)
    const removed = await a.api('DELETE', '/api/buckets/replica-bucket/objects/replicated.txt?permanent=true')
    assert.equal(removed.status, 200)
    await waitFor(async () => (await b.get('replica-bucket', 'replicated.txt')).status === 404, 20000, 'delete to replicate')

    // ---- tasks are reported and completed, not stuck pending
    const tasks = await a.api('GET', '/api/admin/replication/tasks')
    const mine = tasks.body.tasks.filter((row) => (row.path || '').startsWith('replicated.txt'))
    assert.ok(mine.length >= 2, `expected tasks, got ${JSON.stringify(mine)}`)
    assert.ok(mine.every((row) => row.status === 'done'), `all tasks should be done: ${JSON.stringify(mine.map((r) => [r.op, r.status]))}`)

    const stats = await a.api('GET', '/api/admin/replication')
    assert.equal(stats.status, 200)
    assert.ok(stats.body.stats)
})

test('replication tasks are only queued for matching peers', async (t) => {
    const a = await bootNode('node-a', 'az1')
    const b = await bootNode('node-b', 'az2')
    t.after(async () => {
        await a.stop()
        await b.stop()
    })

    // the peer only replicates the "logs/" prefix of replica-bucket
    await link(a, b, { prefix: 'logs/' })
    await a.api('POST', '/api/buckets', { name: 'replica-bucket' })

    await a.put('replica-bucket', 'logs/kept.txt', 'inside the prefix')
    await a.put('replica-bucket', 'other/skipped.txt', 'outside the prefix')

    await waitFor(async () => (await b.get('replica-bucket', 'logs/kept.txt')).status === 200, 20000, 'prefixed object')

    // give the worker a couple of cycles to prove it does not copy the other key
    await new Promise((resolve) => { setTimeout(resolve, 3000) })
    assert.equal((await b.get('replica-bucket', 'other/skipped.txt')).status, 404, 'objects outside the prefix must not replicate')

    const tasks = await a.api('GET', '/api/admin/replication/tasks')
    assert.equal(tasks.body.tasks.some((row) => (row.path || '').startsWith('other/')), false)
})

test('the inbound endpoint rejects unsigned, tampered and replayed pushes', async (t) => {
    const b = await bootNode('node-b', 'az2')
    t.after(async () => { await b.stop() })

    // register a peer that A will impersonate
    await b.api('POST', '/api/admin/replication', {
        name: 'peer-a', endpoint: 'http://127.0.0.1:1', bucket: 'replica-bucket', accessKeyId: 'repl-key', secret: PEER_SECRET, direction: 'inbound',
    })

    const meta = Buffer.from(JSON.stringify({ op: 'PUT', key: 'evil.txt', bucket: 'replica-bucket', sourceRegion: 'az1' })).toString('base64')
    const body = Buffer.from('payload')
    const url = `${b.base}/_internal/replication/objects`
    const sign = (timestamp, secret = PEER_SECRET) => util.hmacSha256(secret, `${timestamp}\n${meta}\n${util.sha256(body)}`)

    const call = (headers) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/octet-stream', ...headers }, body })
    const push = (extra = {}, { timestamp = Date.now(), secret = PEER_SECRET, peer = 'peer-a' } = {}) => call({
        'x-ddrive-peer': peer,
        'x-ddrive-meta': meta,
        'x-ddrive-timestamp': String(timestamp),
        'x-ddrive-signature': sign(timestamp, secret),
        'x-ddrive-access-key': 'repl-key',
        ...extra,
    })

    // no signature at all
    assert.equal((await call({})).status, 403)

    // unknown peer (valid signature for a peer that is not registered)
    assert.equal((await push({}, { peer: 'ghost' })).status, 403)

    // correct peer, wrong signature
    assert.equal((await push({ 'x-ddrive-signature': 'deadbeef' })).status, 403)

    // correct signature but signed with the wrong secret
    assert.equal((await push({ 'x-ddrive-signature': sign(Date.now(), 'not-the-secret') })).status, 403)

    // correct signature but a stale timestamp (replay)
    assert.equal((await push({}, { timestamp: Date.now() - 3600 * 1000 })).status, 403)

    // signature over different content than the body
    const metaB = Buffer.from(JSON.stringify({ op: 'PUT', key: 'evil.txt', bucket: 'replica-bucket' })).toString('base64')
    assert.equal((await call({
        'x-ddrive-peer': 'peer-a',
        'x-ddrive-meta': metaB,
        'x-ddrive-timestamp': String(Date.now()),
        'x-ddrive-signature': sign(Date.now()),
    })).status, 403)

    // nothing was applied
    const bucket = await b.context.repo.findOne('bucket', { name: 'replica-bucket' })
    assert.equal(bucket, null, 'no rejected push may create a bucket')

    // ...whereas a correctly signed push is accepted
    const accepted = await push()
    assert.equal(accepted.status, 200, await accepted.text())
    assert.ok(await b.context.buckets.get('replica-bucket'))
})

test('replication is idempotent: the same object is not stored twice', async (t) => {
    const a = await bootNode('node-a', 'az1')
    const b = await bootNode('node-b', 'az2')
    t.after(async () => {
        await a.stop()
        await b.stop()
    })

    await link(a, b)
    await a.api('POST', '/api/buckets', { name: 'replica-bucket' })
    await a.put('replica-bucket', 'once.txt', 'idempotent payload')

    await waitFor(async () => (await b.get('replica-bucket', 'once.txt')).status === 200, 20000, 'first copy')

    const bucket = await b.context.buckets.get('replica-bucket')
    const before = await b.context.repo.count('object_version', { bucketId: bucket.id, path: 'once.txt' })

    // push the identical object again through the internal endpoint
    const node = await b.context.objects.getNode(bucket.id, 'once.txt')
    const meta = Buffer.from(JSON.stringify({
        op: 'PUT',
        key: 'once.txt',
        bucket: 'replica-bucket',
        checksum: node.checksum,
        sourceRegion: 'az1',
    })).toString('base64')
    const body = Buffer.from('idempotent payload')
    const res = await fetch(`${b.base}/_internal/replication/objects`, {
        method: 'POST',
        headers: {
            'content-type': 'application/octet-stream',
            'x-ddrive-peer': 'az2-link',
            'x-ddrive-meta': meta,
            'x-ddrive-timestamp': String(Date.now()),
            'x-ddrive-signature': util.hmacSha256(PEER_SECRET, `${Date.now()}\n${meta}\n${util.sha256(body)}`),
            'x-ddrive-access-key': 'repl-key',
        },
        body,
    })
    assert.equal(res.status, 200)
    assert.equal((await res.json()).applied, false, 'a duplicate push must be a no-op')

    const after = await b.context.repo.count('object_version', { bucketId: bucket.id, path: 'once.txt' })
    assert.equal(after, before, 'no extra version may be created')
})

test('deleting a bucket retires its replication tasks instead of retrying them', async (t) => {
    const a = await bootNode('az1', 'az1')
    t.after(() => a.stop())
    await a.api('POST', '/api/buckets', { name: 'doomed' })
    await a.api('POST', '/api/buckets/doomed/objects/kept.txt', { hello: 'world' })

    const bucket = await a.context.repo.findOne('bucket', { name: 'doomed' })
    await a.context.replication.createPeer({
        name: 'ghost-peer', endpoint: 'http://127.0.0.1:1/s3', accessKeyId: 'AKIAGHOST', secret: 'ghost-secret',
    })
    const node = await a.context.objects.getNode(bucket.id, 'kept.txt')
    const queued = await a.context.replication.enqueue({ bucket, node, op: 'PUT' })
    assert.equal(queued, 1, 'a task must be queued for the peer')
    assert.equal(await a.context.repo.count('replication_task', { bucketId: bucket.id, status: 'pending' }), 1)

    await a.api('DELETE', '/api/buckets/doomed?force=true')

    const pending = await a.context.repo.count('replication_task', { bucketId: bucket.id, status: 'pending' })
    assert.equal(pending, 0, 'no task may keep retrying against a deleted bucket')
    const retired = await a.context.repo.findOne('replication_task', { bucketId: bucket.id })
    assert.equal(retired.status, 'failed')
    assert.equal(retired.nextAttemptAt, null)
    assert.match(String(retired.lastError), /bucket was deleted/)
})

test('a task already in flight when its bucket disappears is not retried', async (t) => {
    const a = await bootNode('az1', 'az1')
    t.after(() => a.stop())
    await a.api('POST', '/api/buckets', { name: 'inflight' })
    const bucket = await a.context.repo.findOne('bucket', { name: 'inflight' })
    await a.context.objects.putObject({
        bucket, path: 'x.txt', stream: require('node:stream').Readable.from([Buffer.from('x')]), contentType: 'text/plain', actor: {},
    })
    await a.context.replication.createPeer({
        name: 'down-peer', endpoint: 'http://127.0.0.1:1/s3', accessKeyId: 'AKIADOWN', secret: 'down-secret',
    })
    const node = await a.context.objects.getNode(bucket.id, 'x.txt')
    assert.equal(await a.context.replication.enqueue({ bucket, node, op: 'PUT' }), 1)

    // simulate the race: the worker picked the task up before the bucket was removed
    const task = await a.context.repo.findOne('replication_task', { bucketId: bucket.id })
    await a.context.repo.update('replication_task', { id: task.id }, { status: 'in-flight' })
    await a.api('DELETE', '/api/buckets/inflight?force=true')
    await a.context.repo.update('replication_task', { id: task.id }, { status: 'pending', nextAttemptAt: new Date() })

    await a.context.replication.processDue()
    const after = await a.context.repo.findOne('replication_task', { id: task.id })
    assert.equal(after.status, 'failed', 'an in-flight task for a deleted bucket must be retired, not re-queued')
    assert.equal(after.nextAttemptAt, null)
})

test('a backfill only queues the buckets the peer is scoped to', async (t) => {
    const a = await bootNode('az1', 'az1')
    t.after(() => a.stop())
    await a.api('POST', '/api/buckets', { name: 'scoped' })
    await a.api('POST', '/api/buckets', { name: 'other' })
    for (const [bucket, key] of [['scoped', 'in.txt'], ['other', 'out.txt']]) {
        const row = await a.context.repo.findOne('bucket', { name: bucket })
        // eslint-disable-next-line no-await-in-loop
        await a.context.objects.putObject({
            bucket: row, path: key, stream: require('node:stream').Readable.from([Buffer.from(key)]), contentType: 'text/plain', actor: {},
        })
    }
    await a.context.replication.createPeer({
        name: 'scoped-peer', endpoint: 'http://127.0.0.1:1/s3', bucket: 'scoped', accessKeyId: 'AKIASCOPED', secret: 'scoped-secret',
    })

    const res = await a.context.replication.backfill('scoped-peer')
    assert.equal(res.queued, 1, 'only the object in the peer bucket may be queued')

    const scoped = await a.context.repo.findOne('bucket', { name: 'scoped' })
    const other = await a.context.repo.findOne('bucket', { name: 'other' })
    const tasks = await a.context.repo.find('replication_task', {})
    assert.equal(tasks.length, 1)
    assert.equal(tasks[0].bucketId, scoped.id)
    assert.notEqual(tasks[0].bucketId, other.id)
})
