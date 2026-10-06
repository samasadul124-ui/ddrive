/**
 * WebDAV class 1/2/3 server: discovery, collections, uploads, ranges, COPY,
 * MOVE, PROPPATCH dead properties, LOCK/UNLOCK and cross-host protection.
 */
const test = require('node:test')
const assert = require('node:assert/strict')

const { createTestServer } = require('./helpers')

const dav = (t, method, path, opts = {}) => t.http.inject({
    method,
    url: `/webdav${path}`,
    headers: { authorization: t.basic, ...(opts.headers || {}) },
    payload: opts.payload,
})

const setup = async (env = {}) => {
    const t = await createTestServer(env)
    await t.json('POST', '/api/buckets', { name: 'dav-bucket', versioning: 'enabled' })

    return t
}

test('discovery: OPTIONS advertises DAV compliance levels', async () => {
    const t = await setup()
    try {
        const res = await dav(t, 'OPTIONS', '/')
        assert.equal(res.statusCode, 200)
        assert.equal(res.headers.dav, '1, 2, 3')
        assert.match(res.headers.allow || '', /PROPFIND/)
        assert.match(res.headers.allow || '', /LOCK/)
    } finally {
        await t.close()
    }
})

test('PROPFIND lists collections and their children', async () => {
    const t = await setup()
    try {
        const root = await dav(t, 'PROPFIND', '/', { headers: { depth: '1' }, payload: '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>' })
        assert.equal(root.statusCode, 207)
        assert.match(root.body, /\/webdav\/dav-bucket/)

        assert.equal((await dav(t, 'MKCOL', '/dav-bucket/dir')).statusCode, 201)
        const put = await dav(t, 'PUT', '/dav-bucket/dir/file.txt', {
            headers: { 'content-type': 'text/plain' }, payload: 'dav content',
        })
        assert.equal(put.statusCode, 201)

        const listing = await dav(t, 'PROPFIND', '/dav-bucket/dir', {
            headers: { depth: '1', 'content-type': 'text/xml' },
            payload: '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/><D:getetag/></D:prop></D:propfind>',
        })
        assert.equal(listing.statusCode, 207)
        assert.match(listing.body, /file\.txt/)
        assert.match(listing.body, /getcontentlength/)

        const missing = await dav(t, 'PROPFIND', '/dav-bucket/nope', { headers: { depth: '0' } })
        assert.equal(missing.statusCode, 404)
    } finally {
        await t.close()
    }
})

test('GET/HEAD/PUT follow HTTP semantics including overwrite and ranges', async () => {
    const t = await setup()
    try {
        const created = await dav(t, 'PUT', '/dav-bucket/u.txt', { headers: { 'content-type': 'text/plain' }, payload: '0123456789' })
        assert.equal(created.statusCode, 201)

        const fetches = await dav(t, 'GET', '/dav-bucket/u.txt')
        assert.equal(fetches.statusCode, 200)
        assert.equal(fetches.body, '0123456789')
        assert.equal(fetches.headers['accept-ranges'], 'bytes')

        const head = await dav(t, 'HEAD', '/dav-bucket/u.txt')
        assert.equal(head.statusCode, 200)
        assert.equal(head.headers['content-length'], '10')

        const ranged = await dav(t, 'GET', '/dav-bucket/u.txt', { headers: { range: 'bytes=2-5' } })
        assert.equal(ranged.statusCode, 206)
        assert.equal(ranged.body, '2345')

        // a second PUT overwrites -> 204, not 201
        const overwrite = await dav(t, 'PUT', '/dav-bucket/u.txt', { headers: { 'content-type': 'text/plain' }, payload: 'replaced' })
        assert.equal(overwrite.statusCode, 204)
        assert.equal((await dav(t, 'GET', '/dav-bucket/u.txt')).body, 'replaced')
    } finally {
        await t.close()
    }
})

test('COPY and MOVE honour the Destination header and Overwrite: F', async () => {
    const t = await setup()
    try {
        await dav(t, 'PUT', '/dav-bucket/src.txt', { headers: { 'content-type': 'text/plain' }, payload: 'move me' })

        const copied = await dav(t, 'COPY', '/dav-bucket/src.txt', { headers: { destination: '/webdav/dav-bucket/copy.txt' } })
        assert.equal(copied.statusCode, 201)
        assert.equal((await dav(t, 'GET', '/dav-bucket/copy.txt')).body, 'move me')
        assert.equal((await dav(t, 'GET', '/dav-bucket/src.txt')).body, 'move me')

        const moved = await dav(t, 'MOVE', '/dav-bucket/copy.txt', { headers: { destination: '/webdav/dav-bucket/moved.txt' } })
        assert.equal(moved.statusCode, 201)
        assert.equal((await dav(t, 'GET', '/dav-bucket/moved.txt')).body, 'move me')
        assert.equal((await dav(t, 'HEAD', '/dav-bucket/copy.txt')).statusCode, 404)

        // Overwrite: F refuses to clobber
        const refuse = await dav(t, 'COPY', '/dav-bucket/src.txt', {
            headers: { destination: '/webdav/dav-bucket/moved.txt', overwrite: 'F' },
        })
        assert.equal(refuse.statusCode, 412)

        // cross-host destinations are rejected
        const crossHost = await dav(t, 'COPY', '/dav-bucket/src.txt', {
            headers: { destination: 'http://evil.example.com/webdav/dav-bucket/x.txt' },
        })
        assert.equal(crossHost.statusCode, 502)
    } finally {
        await t.close()
    }
})

test('PROPPATCH persists dead properties across requests', async () => {
    const t = await setup()
    try {
        await dav(t, 'PUT', '/dav-bucket/props.txt', { headers: { 'content-type': 'text/plain' }, payload: 'x' })

        const patched = await dav(t, 'PROPPATCH', '/dav-bucket/props.txt', {
            headers: { 'content-type': 'text/xml' },
            payload: '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:test"><D:set><D:prop><Z:custom>value123</Z:custom></D:prop></D:set></D:propertyupdate>',
        })
        assert.equal(patched.statusCode, 207)

        const read = await dav(t, 'PROPFIND', '/dav-bucket/props.txt', {
            headers: { depth: '0', 'content-type': 'text/xml' },
            payload: '<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:Z="urn:test"><D:prop><Z:custom/></D:prop></D:propfind>',
        })
        assert.match(read.body, /value123/)
    } finally {
        await t.close()
    }
})

test('LOCK blocks other writers until UNLOCK', async () => {
    const t = await setup()
    try {
        await dav(t, 'PUT', '/dav-bucket/locked.txt', { headers: { 'content-type': 'text/plain' }, payload: 'lock me' })

        const locked = await dav(t, 'LOCK', '/dav-bucket/locked.txt', {
            headers: { 'content-type': 'text/xml', timeout: 'Second-3600' },
            payload: '<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>mailto:t@example.com</D:href></D:owner></D:lockinfo>',
        })
        assert.equal(locked.statusCode, 200)
        const token = locked.headers['lock-token']
        assert.ok(token, 'LOCK must return a Lock-Token header')

        const blocked = await dav(t, 'PUT', '/dav-bucket/locked.txt', { headers: { 'content-type': 'text/plain' }, payload: 'should fail' })
        assert.equal(blocked.statusCode, 423)

        const allowed = await dav(t, 'PUT', '/dav-bucket/locked.txt', {
            headers: { 'content-type': 'text/plain', if: `(${token})` }, payload: 'with token',
        })
        assert.equal(allowed.statusCode, 204)

        const refresh = await dav(t, 'LOCK', '/dav-bucket/locked.txt', { headers: { if: `(${token})`, timeout: 'Second-7200' } })
        assert.equal(refresh.statusCode, 200)

        const unlocked = await dav(t, 'UNLOCK', '/dav-bucket/locked.txt', { headers: { 'lock-token': token } })
        assert.equal(unlocked.statusCode, 204)
        assert.equal((await dav(t, 'PUT', '/dav-bucket/locked.txt', { headers: { 'content-type': 'text/plain' }, payload: 'free again' })).statusCode, 204)
    } finally {
        await t.close()
    }
})

test('DELETE removes files, refuses non-empty collections and recurses with Depth', async () => {
    const t = await setup()
    try {
        await dav(t, 'MKCOL', '/dav-bucket/tree')
        await dav(t, 'MKCOL', '/dav-bucket/tree/sub')
        await dav(t, 'PUT', '/dav-bucket/tree/sub/deep.txt', { headers: { 'content-type': 'text/plain' }, payload: 'deep' })

        const refused = await dav(t, 'DELETE', '/dav-bucket/tree')
        assert.equal(refused.statusCode, 409)

        const recursive = await dav(t, 'DELETE', '/dav-bucket/tree', { headers: { depth: 'infinity' } })
        assert.equal(recursive.statusCode, 204)
        assert.equal((await dav(t, 'HEAD', '/dav-bucket/tree/sub/deep.txt')).statusCode, 404)
        assert.equal((await dav(t, 'PROPFIND', '/dav-bucket/tree', { headers: { depth: '0' } })).statusCode, 404)
    } finally {
        await t.close()
    }
})

test('with AUTH_MODE=basic, anonymous WebDAV requests are challenged with Basic auth', async () => {
    const t = await setup({ AUTH_MODE: 'basic' })
    try {
        const res = await t.http.inject({ method: 'PROPFIND', url: '/webdav/', headers: { depth: '0' } })
        assert.equal(res.statusCode, 401)
        assert.match(res.headers['www-authenticate'], /Basic/)
    } finally {
        await t.close()
    }
})
