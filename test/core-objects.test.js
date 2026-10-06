/**
 * Object core: chunked writes, versioning, multipart, copy/move, tags,
 * retention and the recursive-delete regression.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const { Readable } = require('node:stream')

const { createTestServer } = require('./helpers')

const ACTOR = { id: null, name: 'tester', type: 'user' }

const setup = async () => {
    const t = await createTestServer()
    const bucket = await t.context.buckets.create('unit-bucket', { ownerId: null, versioning: 'enabled' })

    return { t, bucket }
}

const put = (t, bucket, path, body, opts = {}) => t.context.objects.putObject({
    bucket,
    path,
    stream: Readable.from([Buffer.from(body)]),
    contentType: 'text/plain',
    actor: ACTOR,
    ...opts,
})

const read = async (t, bucket, path, versionId) => {
    const { version } = await t.context.objects.getVersion(bucket, path, versionId)
    const out = await t.context.objects.stream(version)
    const chunks = []
    for await (const chunk of out.stream) chunks.push(chunk)

    return Buffer.concat(chunks).toString()
}

const auditRows = (t, action, extra = {}) => t.context.audit.query({ action, limit: 100, ...extra })

test('putObject stores a readable object and audits the encryption envelope', async () => {
    const { t, bucket } = await setup()
    try {
        const result = await put(t, bucket, 'docs/hello.txt', 'hello ddrive world')

        assert.equal(result.size, 18)
        assert.match(result.etag, /^[0-9a-f]{32}$/)
        assert.equal(await read(t, bucket, 'docs/hello.txt'), 'hello ddrive world')

        const rows = await auditRows(t, 'object.put', { objectKey: 'docs/hello.txt' })
        assert.equal(rows.length, 1)
        const [event] = rows
        assert.equal(event.bucket, 'unit-bucket')
        assert.equal(event.actor, 'tester')
        assert.equal(event.result, 'success')
        assert.equal(event.detail.size, 18)
        assert.deepEqual(event.detail.encryption, {
            enabled: true, algorithm: 'aes-256-gcm', keyId: event.detail.encryption.keyId, envelope: true,
        })
        assert.match(event.detail.encryption.keyId, /^local:/)
    } finally {
        await t.close()
    }
})

test('versioning keeps history and a delete marker restores the previous version', async () => {
    const { t, bucket } = await setup()
    try {
        await put(t, bucket, 'versioned.txt', 'v1')
        await put(t, bucket, 'versioned.txt', 'v2')

        const versions = await t.context.objects.listVersions(bucket, { prefix: 'versioned.txt' })
        assert.equal(versions.versions.length, 2)
        assert.equal(versions.versions.filter((v) => v.isLatest).length, 1)
        assert.equal(await read(t, bucket, 'versioned.txt'), 'v2')

        const first = versions.versions.find((v) => !v.isLatest)
        assert.equal(await read(t, bucket, 'versioned.txt', first.id), 'v1')

        const removed = await t.context.objects.deleteObject({ bucket, path: 'versioned.txt', actor: ACTOR })
        assert.equal(removed.deleteMarker, true)
        await assert.rejects(() => t.context.objects.getVersion(bucket, 'versioned.txt'), { code: 'NoSuchKey' })

        const markers = await auditRows(t, 'object.delete_marker')
        assert.equal(markers.length, 1)
        assert.equal(markers[0].objectKey, 'versioned.txt')

        // removing the delete marker brings the object back
        await t.context.objects.deleteObject({ bucket, path: 'versioned.txt', versionId: removed.versionId, actor: ACTOR })
        assert.equal(await read(t, bucket, 'versioned.txt'), 'v2')

        const versionDeletes = await auditRows(t, 'object.version.delete')
        assert.equal(versionDeletes.length, 1)
    } finally {
        await t.close()
    }
})

test('copy and move rewrite objects and are audited', async () => {
    const { t, bucket } = await setup()
    try {
        await put(t, bucket, 'src/a.txt', 'payload')

        await t.context.objects.copy(
            { bucket, path: 'src/a.txt' },
            { bucket, path: 'dst/b.txt' },
            { actor: ACTOR },
        )
        assert.equal(await read(t, bucket, 'dst/b.txt'), 'payload')

        await t.context.objects.move(bucket, 'dst/b.txt', 'moved/c.txt', { actor: ACTOR })
        assert.equal(await read(t, bucket, 'moved/c.txt'), 'payload')
        await assert.rejects(() => t.context.objects.getVersion(bucket, 'dst/b.txt'), { code: 'NoSuchKey' })

        const copies = await auditRows(t, 'object.copy')
        assert.equal(copies.length, 1)
        assert.equal(copies[0].objectKey, 'dst/b.txt')
        assert.equal(copies[0].detail.source, 'unit-bucket/src/a.txt')
        assert.equal(copies[0].detail.encryption.enabled, true)

        const moves = await auditRows(t, 'object.move')
        assert.equal(moves.length, 1)
        assert.equal(moves[0].detail.to, 'moved/c.txt')
        assert.equal(moves[0].detail.from, 'dst/b.txt')
    } finally {
        await t.close()
    }
})

test('tags, retention and legal hold are audited', async () => {
    const { t } = await setup()
    const bucket = await t.context.buckets.create('locked-bucket', { ownerId: null, versioning: 'enabled', objectLockEnabled: true })
    try {
        await put(t, bucket, 'tagged.txt', 'x')
        await t.context.objects.setTags(bucket, 'tagged.txt', { team: 'core', env: 'test' }, ACTOR)
        assert.deepEqual(await t.context.objects.getTags(bucket, 'tagged.txt'), { team: 'core', env: 'test' })

        await t.context.objects.setRetention(bucket, 'tagged.txt', { mode: 'GOVERNANCE', retainUntil: new Date(Date.now() + 86400000) }, ACTOR)
        assert.equal((await t.context.objects.getRetention(bucket, 'tagged.txt')).mode, 'GOVERNANCE')
        await t.context.objects.setLegalHold(bucket, 'tagged.txt', true, ACTOR)
        assert.equal((await t.context.objects.getRetention(bucket, 'tagged.txt')).legalHold, true)

        const taggingRows = await auditRows(t, 'object.tagging')
        assert.equal(taggingRows.length, 1)
        assert.equal(taggingRows[0].detail.tags.team, 'core')
        // setLegalHold delegates to setRetention, so both mutations are recorded
        const retention = await auditRows(t, 'object.retention')
        assert.equal(retention.length, 2)
        assert.equal(retention[0].detail.legalHold, true)
        assert.equal(retention[1].detail.mode, 'GOVERNANCE')
        const holds = await auditRows(t, 'object.legal_hold')
        assert.equal(holds.length, 1)
        assert.equal(holds[0].detail.legalHold, true)
    } finally {
        await t.close()
    }
})

test('multipart upload assembles parts and records a single audited put', async () => {
    const { t, bucket } = await setup()
    try {
        const upload = await t.context.objects.initiateMultipart({ bucket, path: 'big.bin', contentType: 'application/octet-stream', actor: ACTOR })
        assert.equal(upload.name, 'big.bin')

        const part1 = Buffer.alloc(1024, 'a')
        const part2 = Buffer.alloc(512, 'b')
        await t.context.objects.uploadPart(bucket, upload.uploadId, 1, Readable.from([part1]))
        await t.context.objects.uploadPart(bucket, upload.uploadId, 2, Readable.from([part2]))

        const parts = await t.context.objects.listParts(bucket, upload.uploadId)
        assert.equal(parts.length, 2)

        const completed = await t.context.objects.completeMultipart(
            bucket, upload.uploadId, [{ partNumber: 1 }, { partNumber: 2 }], ACTOR,
        )
        assert.equal(completed.size, 1536)
        assert.equal(await read(t, bucket, 'big.bin', completed.versionId), `${'a'.repeat(1024)}${'b'.repeat(512)}`)

        const puts = await auditRows(t, 'object.put', { objectKey: 'big.bin' })
        assert.equal(puts.length, 1)
        assert.equal(puts[0].detail.multipart, true)
        assert.equal(puts[0].detail.parts, 2)
        assert.equal(puts[0].detail.encryption.enabled, true)

        assert.equal((await auditRows(t, 'multipart.initiate')).length, 1)
    } finally {
        await t.close()
    }
})

test('aborting a multipart upload discards parts and is audited', async () => {
    const { t, bucket } = await setup()
    try {
        const upload = await t.context.objects.initiateMultipart({ bucket, path: 'aborted.bin', actor: ACTOR })
        await t.context.objects.uploadPart(bucket, upload.uploadId, 1, Readable.from([Buffer.alloc(64, 'z')]))
        await t.context.objects.abortMultipart(bucket, upload.uploadId, ACTOR)

        // the upload is gone from the in-progress list and its parts were dropped
        const pending = await t.context.objects.listMultipartUploads(bucket)
        assert.equal(pending.some((row) => row.id === upload.uploadId), false)
        assert.equal((await t.context.repo.find('multipart_part', { uploadId: upload.uploadId })).length, 0)

        const aborts = await auditRows(t, 'multipart.abort')
        assert.equal(aborts.length, 1)
        assert.equal(aborts[0].objectKey, 'aborted.bin')
        assert.equal(aborts[0].detail.uploadId, upload.uploadId)
        assert.equal(aborts[0].detail.partsDiscarded, 1)
    } finally {
        await t.close()
    }
})

test('recursive delete removes a subtree without orphaning children', async () => {
    const { t, bucket } = await setup()
    try {
        await put(t, bucket, 'tree/a.txt', 'a')
        await put(t, bucket, 'tree/nested/b.txt', 'b')

        await t.context.objects.deleteObject({
            bucket, path: 'tree', recursive: true, permanent: true, actor: ACTOR,
        })

        assert.equal(await t.context.objects.getNode(bucket.id, 'tree/a.txt'), null)
        assert.equal(await t.context.objects.getNode(bucket.id, 'tree/nested/b.txt'), null)
        assert.equal(await t.context.objects.getNode(bucket.id, 'tree'), null)

        const listing = await t.context.objects.list({ bucket, prefix: 'tree/' })
        assert.equal(listing.contents.length, 0)

        // writing the same key again must not resurrect the old rows
        await put(t, bucket, 'tree/a.txt', 'fresh')
        const again = await t.context.objects.list({ bucket, prefix: 'tree/' })
        assert.equal(again.contents.length, 1)
        assert.equal(await read(t, bucket, 'tree/a.txt'), 'fresh')

        assert.ok((await auditRows(t, 'directory.delete')).length >= 1)
    } finally {
        await t.close()
    }
})

test('deleting a non-empty prefix without recursive is a no-op (S3 semantics)', async () => {
    const { t, bucket } = await setup()
    try {
        await put(t, bucket, 'keep/a.txt', 'a')
        const result = await t.context.objects.deleteObject({ bucket, path: 'keep', actor: ACTOR })

        assert.equal(result.deleted, false)
        assert.equal(await read(t, bucket, 'keep/a.txt'), 'a')
    } finally {
        await t.close()
    }
})
