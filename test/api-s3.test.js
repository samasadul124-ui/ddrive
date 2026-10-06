/**
 * S3 compatible API over the /s3 mount, signed with the platform's SigV4
 * implementation. (Interop with the official AWS SDK signer is covered by the
 * external harness in /home/user/s3test.)
 */
const test = require('node:test')
const assert = require('node:assert/strict')

const { createTestServer, createAccessKey, s3 } = require('./helpers')
const sigv4 = require('../src/lib/sigv4')

const setup = async (env = {}) => {
    const t = await createTestServer(env)
    t.credentials = await createAccessKey(t)

    return t
}

test('signed requests create a bucket, store and read an object', async () => {
    const t = await setup()
    try {
        const created = await s3(t, { method: 'PUT', path: '/s3-bucket' })
        assert.equal(created.statusCode, 200)

        const put = await s3(t, {
            method: 'PUT',
            path: '/s3-bucket/folder/hello.txt',
            payload: 'hello s3 world',
            headers: { 'content-type': 'text/plain' },
        })
        assert.equal(put.statusCode, 200)
        
        const got = await s3(t, { method: 'GET', path: '/s3-bucket/folder/hello.txt' })
        assert.equal(got.statusCode, 200)
        assert.equal(got.body, 'hello s3 world')
        assert.equal(got.headers['content-type'], 'text/plain')

        const head = await s3(t, { method: 'HEAD', path: '/s3-bucket/folder/hello.txt' })
        assert.equal(head.statusCode, 200)
        assert.equal(head.headers['content-length'], '14')

        const missing = await s3(t, { method: 'GET', path: '/s3-bucket/nope.txt' })
        assert.equal(missing.statusCode, 404)
        assert.match(missing.body, /<Code>NoSuchKey<\/Code>/)

        const noBucket = await s3(t, { method: 'GET', path: '/ghost-bucket/x' })
        assert.equal(noBucket.statusCode, 404)
        assert.match(noBucket.body, /<Code>NoSuchBucket<\/Code>/)
    } finally {
        await t.close()
    }
})

test('with AUTH_MODE=basic, unsigned and badly signed requests are rejected', async () => {
    const t = await setup({ AUTH_MODE: 'basic' })
    try {
        const anonymous = await t.http.inject({ method: 'PUT', url: '/s3/denied-bucket' })
        assert.equal(anonymous.statusCode, 403)
        assert.match(anonymous.body, /<Code>AccessDenied<\/Code>/)

        const bad = await s3(t, {
            method: 'PUT', path: '/denied-bucket', credentials: { accessKeyId: t.credentials.accessKeyId, secretAccessKey: 'wrong-secret' },
        })
        assert.equal(bad.statusCode, 403)
        assert.match(bad.body, /<Code>SignatureDoesNotMatch<\/Code>/)
    } finally {
        await t.close()
    }
})

test('listing, ranges, copy and delete follow S3 semantics', async () => {
    const t = await setup()
    try {
        await s3(t, { method: 'PUT', path: '/list-bucket' })
        await s3(t, { method: 'PUT', path: '/list-bucket/a.txt', payload: 'aaa', headers: { 'content-type': 'text/plain' } })
        await s3(t, { method: 'PUT', path: '/list-bucket/dir/b.txt', payload: 'bbb', headers: { 'content-type': 'text/plain' } })

        const list = await s3(t, { method: 'GET', path: '/list-bucket' })
        assert.equal(list.statusCode, 200)
        assert.match(list.body, /<Key>a\.txt<\/Key>/)
        assert.match(list.body, /<Key>dir\/b\.txt<\/Key>/)

        const delimited = await s3(t, { method: 'GET', path: '/list-bucket', query: { delimiter: '/', prefix: '' } })
        assert.match(delimited.body, /<CommonPrefixes><Prefix>dir\/<\/Prefix><\/CommonPrefixes>/)

        const range = await s3(t, { method: 'GET', path: '/list-bucket/a.txt', headers: { range: 'bytes=1-2' } })
        assert.equal(range.statusCode, 206)
        assert.equal(range.body, 'aa')

        const copied = await s3(t, {
            method: 'PUT', path: '/list-bucket/c.txt', headers: { 'x-amz-copy-source': '/list-bucket/a.txt' },
        })
        assert.equal(copied.statusCode, 200)
        assert.match(copied.body, /<CopyObjectResult\b/)

        const copiedBody = await s3(t, { method: 'GET', path: '/list-bucket/c.txt' })
        assert.equal(copiedBody.body, 'aaa')

        const removed = await s3(t, { method: 'DELETE', path: '/list-bucket/c.txt' })
        assert.equal(removed.statusCode, 204)
        assert.equal((await s3(t, { method: 'GET', path: '/list-bucket/c.txt' })).statusCode, 404)

        // a non-empty bucket can only be deleted with ?force=true
        assert.equal((await s3(t, { method: 'DELETE', path: '/list-bucket' })).statusCode, 409)
        assert.equal((await s3(t, { method: 'DELETE', path: '/list-bucket', query: { force: 'true' } })).statusCode, 204)
    } finally {
        await t.close()
    }
})

test('multipart upload through the S3 API reassembles the parts', async () => {
    const t = await setup()
    try {
        await s3(t, { method: 'PUT', path: '/mp-bucket' })

        const initiated = await s3(t, { method: 'POST', path: '/mp-bucket/big.bin', query: { uploads: '' } })
        assert.equal(initiated.statusCode, 200)
        const uploadId = /<UploadId>([^<]+)<\/UploadId>/.exec(initiated.body)[1]

        const part1 = Buffer.alloc(1024, 'a')
        const part2 = Buffer.alloc(1024, 'b')
        const p1 = await s3(t, { method: 'PUT', path: '/mp-bucket/big.bin', query: { partNumber: '1', uploadId }, payload: part1 })
        const p2 = await s3(t, { method: 'PUT', path: '/mp-bucket/big.bin', query: { partNumber: '2', uploadId }, payload: part2 })
        assert.equal(p1.statusCode, 200)
        assert.equal(p2.statusCode, 200)

        const complete = await s3(t, {
            method: 'POST',
            path: '/mp-bucket/big.bin',
            query: { uploadId },
            payload: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>${p1.headers.etag}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>${p2.headers.etag}</ETag></Part></CompleteMultipartUpload>`,
            headers: { 'content-type': 'application/xml' },
        })
        assert.equal(complete.statusCode, 200)
        assert.match(complete.body, /<CompleteMultipartUploadResult\b/)

        const head = await s3(t, { method: 'HEAD', path: '/mp-bucket/big.bin' })
        assert.equal(head.headers['content-length'], '2048')

        const body = await s3(t, { method: 'GET', path: '/mp-bucket/big.bin' })
        assert.equal(body.body.length, 2048)
        assert.equal(body.body.slice(0, 4), 'aaaa')
        assert.equal(body.body.slice(-4), 'bbbb')
    } finally {
        await t.close()
    }
})

test('presigned URLs serve objects without credentials', async () => {
    const t = await setup()
    try {
        await s3(t, { method: 'PUT', path: '/presign-bucket' })
        await s3(t, { method: 'PUT', path: '/presign-bucket/hello.txt', payload: 'presigned body', headers: { 'content-type': 'text/plain' } })

        const url = sigv4.presign({
            method: 'GET', url: 'http://127.0.0.1:3111/s3/presign-bucket/hello.txt',
        }, t.credentials, { region: 'us-east-1', expiresIn: 300 })
        const parsed = new URL(url)

        const res = await t.http.inject({ method: 'GET', url: `${parsed.pathname}${parsed.search}`, headers: { host: parsed.host } })
        assert.equal(res.statusCode, 200)
        assert.equal(res.body, 'presigned body')

        // tampering with the signature fails
        const tampered = `${parsed.pathname}${parsed.search.replace(/X-Amz-Signature=[0-9a-f]/, 'X-Amz-Signature=f')}`
        const bad = await t.http.inject({ method: 'GET', url: tampered, headers: { host: parsed.host } })
        assert.equal(bad.statusCode, 403)
    } finally {
        await t.close()
    }
})

test('object tagging and versioning round-trip through the S3 API', async () => {
    const t = await setup()
    try {
        await s3(t, { method: 'PUT', path: '/v-bucket' })
        await s3(t, { method: 'PUT', path: '/v-bucket', query: { versioning: '' }, payload: '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>', headers: { 'content-type': 'application/xml' } })

        await s3(t, { method: 'PUT', path: '/v-bucket/obj.txt', payload: 'v1', headers: { 'content-type': 'text/plain' } })
        await s3(t, { method: 'PUT', path: '/v-bucket/obj.txt', payload: 'v2', headers: { 'content-type': 'text/plain' } })

        const versions = await s3(t, { method: 'GET', path: '/v-bucket', query: { versions: '' } })
        assert.equal(versions.statusCode, 200)
        assert.match(versions.body, /<Version>/)
        assert.equal((versions.body.match(/<Version>/g) || []).length, 2)

        const tagged = await s3(t, {
            method: 'PUT', path: '/v-bucket/obj.txt', query: { tagging: '' }, payload: '<Tagging><TagSet><Tag><Key>team</Key><Value>core</Value></Tag></TagSet></Tagging>', headers: { 'content-type': 'application/xml' },
        })
        assert.equal(tagged.statusCode, 200)

        const tags = await s3(t, { method: 'GET', path: '/v-bucket/obj.txt', query: { tagging: '' } })
        assert.match(tags.body, /<Key>team<\/Key><Value>core<\/Value>/)

        const removed = await s3(t, { method: 'DELETE', path: '/v-bucket/obj.txt' })
        assert.equal(removed.statusCode, 204)
        const gone = await s3(t, { method: 'GET', path: '/v-bucket/obj.txt' })
        assert.equal(gone.statusCode, 404)
        assert.equal(gone.headers['x-amz-delete-marker'], 'true')
    } finally {
        await t.close()
    }
})

test('an object upload into a missing bucket fails instead of vanishing', async () => {
    // regression: PUT /bucket/key on a bucket that does not exist used to be
    // handled as a bucket creation - it returned 200 and stored nothing, so
    // `aws s3 cp file s3://new-bucket/key` looked successful while losing the
    // file. S3 answers NoSuchBucket and so must we.
    const t = await setup()
    try {
        const missing = await s3(t, { method: 'PUT', path: '/not-there/file.txt', payload: 'must not be swallowed' })
        assert.equal(missing.statusCode, 404, missing.body)
        assert.match(missing.body, /<Code>NoSuchBucket<\/Code>/)
        assert.equal((await t.json('GET', '/api/buckets')).statusCode, 200)
        assert.equal(t.body(await t.json('GET', '/api/buckets')).buckets.some((b) => b.name === 'not-there'), false, 'a failed upload must not create the bucket')

        // creating the bucket explicitly is the documented way, and then the
        // same upload stores the object
        const created = await s3(t, { method: 'PUT', path: '/proper-bucket' })
        assert.equal(created.statusCode, 200)
        const put = await s3(t, { method: 'PUT', path: '/proper-bucket/file.txt', payload: 'stored properly' })
        assert.ok([200, 201].includes(put.statusCode), put.body)
        const got = await s3(t, { method: 'GET', path: '/proper-bucket/file.txt' })
        assert.equal(got.statusCode, 200)
        assert.equal(got.body, 'stored properly')

        // a streaming (aws-chunked) upload into a missing bucket is rejected too
        // (bucket existence is checked before the payload is decoded)
        const chunked = await s3(t, {
            method: 'PUT',
            path: '/also-missing/chunked.txt',
            payload: 'x',
            headers: { 'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD' },
        })
        assert.equal(chunked.statusCode, 404, chunked.body)
        assert.match(chunked.body, /<Code>NoSuchBucket<\/Code>/)
    } finally {
        await t.close()
    }
})
