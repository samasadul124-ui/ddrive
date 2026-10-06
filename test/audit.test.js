/**
 * Tamper-evident audit log: hash chain, tamper detection, compliance views
 * (encryption filter, roll-up, CSV export) and retention pruning.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const { Readable } = require('node:stream')

const { createTestServer } = require('./helpers')

const ACTOR = { name: 'tester', type: 'user' }

const writeObject = async (t, bucket, path, body) => t.context.objects.putObject({
    bucket, path, stream: Readable.from([Buffer.from(body)]), contentType: 'text/plain', actor: ACTOR,
})

test('audit chain verifies and sees every appended record', async () => {
    const t = await createTestServer()
    try {
        const bucket = await t.context.buckets.create('audit-bucket', { ownerId: null, versioning: 'enabled' })
        await writeObject(t, bucket, 'a.txt', 'one')
        await writeObject(t, bucket, 'b.txt', 'two')
        await t.context.objects.deleteObject({ bucket, path: 'a.txt', actor: ACTOR })

        const result = await t.context.audit.verify()
        assert.equal(result.ok, true)
        assert.ok(result.checked >= 4)
        assert.match(result.head, /^[0-9a-f]{64}$/)

        const rows = await t.context.audit.query({ limit: 100 })
        const actions = rows.map((row) => row.action)
        assert.ok(actions.includes('object.put'))
        assert.ok(actions.includes('object.delete_marker'))
        // every record carries its request context and the chained hashes
        rows.forEach((row) => {
            assert.ok(row.id)
            assert.ok(row.ts)
            assert.equal(row.hash.length, 64)
            assert.ok(row.prevHash === 'GENESIS' || row.prevHash.length === 64)
        })
    } finally {
        await t.close()
    }
})

test('mutating a historical record breaks the chain', async () => {
    const t = await createTestServer()
    try {
        const bucket = await t.context.buckets.create('tamper-bucket', { ownerId: null })
        await writeObject(t, bucket, 'x.txt', 'x')

        const rows = await t.context.repo.find('audit_event', { action: 'object.put' }, { orderBy: [{ column: 'seq', dir: 'asc' }] })
        const target = rows[0]
        await t.context.repo.update('audit_event', { id: target.id }, { actor: 'attacker' })

        const result = await t.context.audit.verify()
        assert.equal(result.ok, false)
        assert.equal(result.brokenAt.seq, target.seq)
        assert.notEqual(result.brokenAt.expected, result.brokenAt.actual)
    } finally {
        await t.close()
    }
})

test('encryption filter, roll-up and CSV export describe encrypted writes', async () => {
    const t = await createTestServer()
    try {
        const bucket = await t.context.buckets.create('enc-bucket', { ownerId: null })
        await writeObject(t, bucket, 'secret.txt', 'classified')
        await writeObject(t, bucket, 'plain.txt', 'not a secret')

        const page = await t.context.audit.query({ encrypted: true, limit: 1 })
        assert.equal(page.length, 1)
        assert.equal(page[0].detail.encryption.enabled, true)
        assert.equal(page[0].detail.encryption.algorithm, 'aes-256-gcm')

        const summary = await t.context.audit.encryptionSummary({ bucket: 'enc-bucket' })
        assert.equal(summary.encrypted, 2)
        assert.equal(summary.plaintext, 0)
        assert.equal(summary.encryptedRatio, 1)
        assert.deepEqual(summary.algorithms, [{ algorithm: 'aes-256-gcm', count: 2 }])
        assert.equal(summary.keys.length, 1)
        assert.ok(summary.lastEncryptedAt)

        const csv = await t.context.audit.exportCsv({ encrypted: true })
        const [header, ...lines] = csv.split('\n')
        assert.match(header, /^seq,ts,actor,actorType,action,bucket,key,versionId,result,statusCode,encryption,algorithm,keyId,detail,ip,requestId$/)
        assert.equal(lines.length, 2)
        assert.match(lines[0], /"aes-256-gcm","local:/)
    } finally {
        await t.close()
    }
})

test('retention pruning drops old rows and records the prune', async () => {
    const t = await createTestServer()
    try {
        const bucket = await t.context.buckets.create('prune-bucket', { ownerId: null })
        await writeObject(t, bucket, 'old.txt', 'old')

        await t.context.audit.record({ action: 'test.ancient', actor: 'system', ts: new Date(Date.now() - 90 * 86400000) })
        const before = await t.context.repo.count('audit_event')
        const { pruned } = await t.context.audit.prune(30)

        assert.equal(pruned, 1)
        assert.equal(await t.context.repo.count('audit_event'), before)
        const actions = (await t.context.audit.query({ limit: 100 })).map((row) => row.action)
        assert.ok(actions.includes('audit.prune'))
        assert.equal(actions.includes('test.ancient'), false)
    } finally {
        await t.close()
    }
})

test('append-only JSONL sink mirrors the database', async () => {
    const fs = require('node:fs')
    const path = require('node:path')
    const os = require('node:os')

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ddrive-audit-sink-'))
    const auditFile = path.join(dir, 'audit.jsonl')
    const t = await createTestServer({ AUDIT_LOG_FILE: auditFile })
    try {
        const bucket = await t.context.buckets.create('sink-bucket', { ownerId: null })
        await writeObject(t, bucket, 'logged.txt', 'line')

        const recorded = await t.context.audit.query({ limit: 100 })
        const readLines = () => (fs.existsSync(auditFile) ? fs.readFileSync(auditFile, 'utf8').trim().split('\n').filter(Boolean) : [])
        // the file sink is written asynchronously (fire and forget), so give it a moment
        for (let i = 0; i < 50 && readLines().length < recorded.length; i += 1) await new Promise((resolve) => { setTimeout(resolve, 20) })
        const lines = readLines().map((line) => JSON.parse(line))

        assert.equal(lines.length, recorded.length)
        assert.deepEqual(lines.map((row) => row.action).sort(), recorded.map((row) => row.action).sort())
        const put = lines.find((row) => row.action === 'object.put')
        assert.equal(put.objectKey, 'logged.txt')
        assert.equal(put.detail.encryption.enabled, true)
    } finally {
        fs.rmSync(dir, { recursive: true, force: true })
        await t.close()
    }
})

test('records carrying undefined fields still verify (the stored shape is the hashed shape)', async () => {
    const t = await createTestServer()
    try {
        // lifecycle.run and friends pass explicit `undefined` values in detail;
        // they must hash and store the same shape or the chain can never verify
        await t.context.audit.record({
            action: 'lifecycle.run',
            actor: 'system',
            actorType: 'system',
            protocol: 'internal',
            detail: { rules: 1, ranAt: new Date(), details: undefined, nested: { also: undefined, ok: true } },
        })
        await t.context.audit.record({ action: 'plain.entry', actor: 'system', detail: { kept: null } })

        const verified = await t.context.audit.verify()
        assert.equal(verified.ok, true, `chain must verify, broke at ${JSON.stringify(verified.brokenAt)}`)

        // and it still detects a real edit
        const rows = await t.context.repo.find('audit_event', {}, { orderBy: [{ column: 'seq', dir: 'asc' }] })
        await t.context.repo.update('audit_event', { id: rows[0].id }, { detail: { tampered: true } })
        const after = await t.context.audit.verify()
        assert.equal(after.ok, false)
    } finally {
        await t.close()
    }
})
