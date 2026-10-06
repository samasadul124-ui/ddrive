/**
 * REST API: panel routes, bucket/object operations, shares, lifecycle,
 * auto-tagging, tiering, admin surface and the IAM endpoints.
 */
const test = require('node:test')
const assert = require('node:assert/strict')

const { createTestServer } = require('./helpers')

const setup = async () => {
    const t = await createTestServer()
    await t.json('POST', '/api/buckets', { name: 'rest-bucket', versioning: 'enabled' })

    return t
}

test('panel: directories and multipart file upload round-trip', async () => {
    const t = await setup()
    try {
        const dir = await t.json('POST', '/api/directories', { name: 'docs', parentId: null })
        assert.equal(dir.statusCode, 201)
        const directory = t.body(dir)

        const listing = await t.json('GET', '/api/directories')
        assert.equal(listing.statusCode, 200)
        assert.ok(t.body(listing).child.directories.some((d) => d.name === 'docs'))

        const boundary = '----ddriveTestBoundary'
        const body = [
            `--${boundary}`,
            'Content-Disposition: form-data; name="file"; filename="note.txt"',
            'Content-Type: text/plain',
            '',
            'panel upload body',
            `--${boundary}--`,
            '',
        ].join('\r\n')
        const uploaded = await t.http.inject({
            method: 'POST',
            url: `/api/files/${directory.id}`,
            headers: { authorization: t.basic, 'content-type': `multipart/form-data; boundary=${boundary}` },
            payload: Buffer.from(body),
        })
        assert.equal(uploaded.statusCode, 201)
        const file = t.body(uploaded)
        assert.equal(file.name, 'note.txt')

        const download = await t.http.inject({ method: 'GET', url: `/api/files/${file.id}/download`, headers: { authorization: t.basic } })
        assert.equal(download.statusCode, 200)
        assert.equal(download.body, 'panel upload body')

        const ranged = await t.http.inject({
            method: 'GET', url: `/api/files/${file.id}/download`, headers: { authorization: t.basic, range: 'bytes=0-4' },
        })
        assert.equal(ranged.statusCode, 206)
        assert.equal(ranged.body, 'panel')

        const meta = await t.json('GET', `/api/files/${file.id}`)
        assert.equal(t.body(meta).name, 'note.txt')
    } finally {
        await t.close()
    }
})

test('buckets and objects: CRUD, listing, versions and tags', async () => {
    const t = await setup()
    try {
        const write = (path, content) => t.http.inject({
            method: 'PUT',
            url: `/api/buckets/rest-bucket/objects/${path}`,
            headers: { authorization: t.basic, 'content-type': 'text/plain' },
            payload: content,
        })

        assert.equal((await write('notes/a.txt', 'notes body')).statusCode, 201)
        assert.equal((await write('notes/b.txt', 'second body')).statusCode, 201)
        assert.equal((await write('other/c.txt', 'third body')).statusCode, 201)

        const download = await t.http.inject({ method: 'GET', url: '/api/buckets/rest-bucket/objects/notes/a.txt/download', headers: { authorization: t.basic } })
        assert.equal(download.body, 'notes body')

        const all = await t.json('GET', '/api/buckets/rest-bucket/objects?recursive=true')
        assert.equal(t.body(all).objects.length, 3)

        const prefixed = await t.json('GET', '/api/buckets/rest-bucket/objects?prefix=notes/&delimiter=/')
        assert.equal(t.body(prefixed).objects.length, 2)

        // second write creates a version
        await write('notes/a.txt', 'notes body v2')
        const versions = await t.json('GET', '/api/buckets/rest-bucket/objects/notes/a.txt/versions')
        assert.equal(t.body(versions).versions.length, 2)
        assert.equal(t.body(versions).versions.filter((v) => v.isLatest).length, 1)

        const tagged = await t.json('PUT', '/api/buckets/rest-bucket/objects/notes/a.txt/tags', { tags: { team: 'core' } })
        assert.equal(tagged.statusCode, 200)
        const tags = await t.json('GET', '/api/buckets/rest-bucket/objects/notes/a.txt/tags')
        assert.equal(t.body(tags).tags.team, 'core')

        const removed = await t.json('DELETE', '/api/buckets/rest-bucket/objects/notes/b.txt')
        assert.equal(removed.statusCode, 200)
        const gone = await t.http.inject({ method: 'GET', url: '/api/buckets/rest-bucket/objects/notes/b.txt/download', headers: { authorization: t.basic } })
        assert.equal(gone.statusCode, 404)
    } finally {
        await t.close()
    }
})

test('recursive prefix delete is repeatable and leaves no orphans', async () => {
    const t = await setup()
    try {
        const write = (path, content) => t.http.inject({
            method: 'PUT',
            url: `/api/buckets/rest-bucket/objects/${path}`,
            headers: { authorization: t.basic, 'content-type': 'text/plain' },
            payload: content,
        })
        await write('tree/a.txt', 'a')
        await write('tree/nested/b.txt', 'b')

        const removed = await t.json('DELETE', '/api/buckets/rest-bucket/objects/tree?recursive=true&permanent=true')
        assert.equal(removed.statusCode, 200)

        const listing = await t.json('GET', '/api/buckets/rest-bucket/objects?prefix=tree/&recursive=true')
        assert.equal(t.body(listing).objects.length, 0)

        // the same key can be written again without resurrecting old rows
        assert.equal((await write('tree/a.txt', 'fresh')).statusCode, 201)
        const again = await t.json('GET', '/api/buckets/rest-bucket/objects?prefix=tree/&recursive=true')
        assert.equal(t.body(again).objects.length, 1)

        const orphans = await t.context.repo.find('directory', { path: 'tree/nested/b.txt' })
        assert.equal(orphans.length, 0)
    } finally {
        await t.close()
    }
})

test('shares can be created, used anonymously and revoked', async () => {
    const t = await setup()
    try {
        await t.http.inject({
            method: 'PUT',
            url: '/api/buckets/rest-bucket/objects/shared.txt',
            headers: { authorization: t.basic, 'content-type': 'text/plain' },
            payload: 'shared content',
        })

        const created = await t.json('POST', '/api/buckets/rest-bucket/shares', { path: 'shared.txt' })
        assert.equal(created.statusCode, 201)
        const { token } = t.body(created)

        const anonymous = await t.http.inject({ method: 'GET', url: `/share/${token}` })
        assert.equal(anonymous.statusCode, 200)
        assert.equal(anonymous.body, 'shared content')

        const listed = await t.json('GET', '/api/buckets/rest-bucket/shares')
        assert.equal(t.body(listed).shares.length, 1)

        const revoked = await t.json('DELETE', `/api/shares/${token}`)
        assert.equal(revoked.statusCode, 204)
        assert.equal((await t.http.inject({ method: 'GET', url: `/share/${token}` })).statusCode, 404)
    } finally {
        await t.close()
    }
})

test('lifecycle, auto-tagging, tiering and search work end to end', async () => {
    const t = await setup()
    try {
        await t.http.inject({
            method: 'PUT',
            url: '/api/buckets/rest-bucket/objects/logs/app.log',
            headers: { authorization: t.basic, 'content-type': 'text/plain' },
            payload: 'log line',
        })

        const rule = await t.json('POST', '/api/admin/lifecycle', {
            bucket: 'rest-bucket', name: 'expire-logs', prefix: 'logs/', expirationDays: 30,
        })
        assert.equal(rule.statusCode, 201)
        assert.equal(t.body(rule).name, 'expire-logs')

        const dryRun = await t.json('POST', '/api/admin/lifecycle/run?dryRun=true')
        assert.equal(t.body(dryRun).dryRun, true)

        const autoTag = await t.json('POST', '/api/admin/auto-tag-rules', {
            name: 'text-files', conditions: { mime: 'text/*' }, tags: { kind: 'text' }, applyOn: 'sweep',
        })
        assert.equal(autoTag.statusCode, 201)

        // a sweep-only rule must actually tag objects that already exist
        const sweep = await t.json('POST', '/api/admin/auto-tag-rules/sweep')
        assert.equal(sweep.statusCode, 200)
        assert.ok(t.body(sweep).scanned >= 1)
        assert.ok(t.body(sweep).tagged >= 1)

        const tiering = await t.json('POST', '/api/admin/tiering/run?dryRun=true')
        assert.equal(tiering.statusCode, 200)

        // auto-tagging namespaces rule tags with `ai:` so a later user tag with
        // the same key wins; search therefore indexes the prefixed key
        const found = await t.json('GET', '/api/admin/search?key=ai:kind&value=text')
        assert.ok(t.body(found).objects.some((o) => o.path === 'logs/app.log'), 'sweep-applied tag must be searchable')

        const misses = await t.json('GET', '/api/admin/search?key=ai:kind&value=nope')
        assert.equal(t.body(misses).objects.length, 0)
    } finally {
        await t.close()
    }
})

test('admin overview, settings, metrics and health endpoints respond', async () => {
    const t = await setup()
    try {
        for (const url of ['/api/admin/overview', '/api/admin/settings', '/api/admin/audit/verify', '/metrics', '/healthz', '/readyz', '/console/', '/api/me']) {
            const res = await t.json('GET', url)
            assert.equal(res.statusCode, 200, `${url} should be 200`)
        }

        const overview = t.body(await t.json('GET', '/api/admin/overview'))
        assert.equal(typeof overview, 'object')

        const verified = t.body(await t.json('GET', '/api/admin/audit/verify'))
        assert.equal(verified.ok, true)
    } finally {
        await t.close()
    }
})

test('unauthenticated requests to the API are rejected', async () => {
    const t = await setup()
    try {
        for (const url of ['/api/buckets', '/api/directories', '/api/admin/overview']) {
            const res = await t.http.inject({ method: 'GET', url })
            assert.equal(res.statusCode, 401, `${url} must require auth`)
        }
    } finally {
        await t.close()
    }
})
