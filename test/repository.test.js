/**
 * Repository layer: filters, transactions and the guard against a filter that
 * silently matches every row.
 */
const test = require('node:test')
const assert = require('node:assert/strict')

const { createTestServer } = require('./helpers')

test('an unrecognised filter object compares by value instead of matching everything', async () => {
    const t = await createTestServer()
    try {
        await t.context.repo.insert('policy', { name: 'first', document: { Statement: [{ Effect: 'Allow', Action: ['*'], Resource: ['*'] }] } })
        await t.context.repo.insert('policy', { name: 'second', document: { Statement: [{ Effect: 'Allow', Action: ['s3:GetObject'], Resource: ['*'] }] } })

        // a document object is not an operator object: it must not become "match any row"
        const bogus = await t.context.repo.findOne('policy', { name: { Statement: [] } })
        assert.equal(bogus, null, 'a document used as a lookup key must not return the first row')

        // real filters still work
        assert.equal((await t.context.repo.findOne('policy', { name: 'second' })).name, 'second')
        assert.equal((await t.context.repo.find('policy', { name: { like: 'ir' } })).length, 1)

        // and the recognised operators are untouched
        const like = await t.context.repo.find('policy', { name: { like: 'fir' } })
        assert.deepEqual(like.map((r) => r.name), ['first'])
        const inList = await t.context.repo.find('policy', { name: { in: ['first', 'second'] } })
        assert.equal(inList.length, 2)
        const emptyIn = await t.context.repo.find('policy', { name: { in: [] } })
        assert.equal(emptyIn.length, 0)
    } finally {
        await t.close()
    }
})

test('json columns round-trip through insert and find', async () => {
    const t = await createTestServer()
    try {
        const document = { Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: ['s3:*'], Resource: ['arn:ddrive:s3:::ddrive/secret/*'] }] }
        await t.context.repo.insert('policy', { name: 'json-doc', document })

        const found = await t.context.repo.findOne('policy', { name: 'json-doc' })
        assert.deepEqual(found.document, document)
    } finally {
        await t.close()
    }
})

test('transactions commit together and roll back on error', async () => {
    const t = await createTestServer()
    try {
        await t.context.repo.transaction(async (tx) => {
            await tx.insert('policy', { name: 'committed', document: {} })
            await tx.insert('policy', { name: 'also-committed', document: {} })
        })
        assert.equal(await t.context.repo.count('policy', { name: 'committed' }), 1)
        assert.equal(await t.context.repo.count('policy', { name: 'also-committed' }), 1)

        await assert.rejects(() => t.context.repo.transaction(async (tx) => {
            await tx.insert('policy', { name: 'rolled-back', document: {} })
            throw new Error('boom')
        }))

        assert.equal(await t.context.repo.count('policy', { name: 'rolled-back' }), 0, 'the failed transaction must not leave rows behind')
    } finally {
        await t.close()
    }
})

test('count, exists, aggregate and ordered pagination behave', async () => {
    const t = await createTestServer()
    try {
        await t.context.buckets.create('page-bucket', { ownerId: null })
        const bucket = await t.context.buckets.get('page-bucket')
        const { Readable } = require('node:stream')
        for (const key of ['a.txt', 'b.txt', 'c.txt']) {
            // eslint-disable-next-line no-await-in-loop
            await t.context.objects.putObject({
                bucket, path: key, stream: Readable.from([Buffer.from(`content of ${key}`)]), contentType: 'text/plain', actor: { name: 'tester' },
            })
        }

        assert.equal(await t.context.repo.count('directory', { bucketId: bucket.id, type: 'file' }), 3)
        assert.equal(await t.context.repo.exists('directory', { bucketId: bucket.id, path: 'a.txt' }), true)
        assert.equal(await t.context.repo.exists('directory', { bucketId: bucket.id, path: 'zzz.txt' }), false)

        const total = await t.context.repo.aggregate('directory', 'sum', 'size', { bucketId: bucket.id, type: 'file' })
        assert.ok(Number(total) > 0)

        const page = await t.context.repo.find('directory', { bucketId: bucket.id, type: 'file' }, {
            orderBy: [{ column: 'path', dir: 'asc' }], limit: 2, offset: 1,
        })
        assert.deepEqual(page.map((r) => r.path), ['b.txt', 'c.txt'])

        const descending = await t.context.repo.find('directory', { bucketId: bucket.id, type: 'file' }, {
            orderBy: [{ column: 'path', dir: 'desc' }], limit: 1,
        })
        assert.equal(descending[0].path, 'c.txt')
    } finally {
        await t.close()
    }
})
