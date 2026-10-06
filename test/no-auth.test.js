/**
 * Authentication mode.
 *
 * DDrive answers without credentials by default (AUTH_MODE=none): the panel,
 * REST API, WebDAV and S3 are usable straight after `npm start`, with no login
 * prompt and no password. Setting AUTH_MODE=basic (or a legacy AUTH=user:pass)
 * puts the password requirement back, and none of these tests may change that.
 *
 * The "disabled" mode is not the same as "public read-only": the request is
 * served as the administrator, so writes work too.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const { Buffer } = require('node:buffer')

const { loadConfig } = require('../src/config')
const { createTestServer, createAccessKey } = require('./helpers')

const basic = (user, pass) => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`

const withoutCredentials = async (t, env = {}) => {
    const server = await createTestServer(env)

    return {
        server,
        // note: no authorization header at all
        get: (url, headers = {}) => server.http.inject({ method: 'GET', url, headers }),
        dav: (url, headers = {}) => server.http.inject({ method: 'PROPFIND', url, headers: { depth: '1', ...headers } }),
        put: (url, payload, headers = {}) => server.http.inject({
            method: 'PUT', url, headers: { 'content-type': 'text/plain', ...headers }, payload,
        }),
    }
}

test('nothing requires credentials by default', async (t) => {
    const t2 = await withoutCredentials(t)
    try {
        // the console and its API
        const panel = await t2.get('/')
        assert.equal(panel.statusCode, 200)
        assert.equal(panel.headers['www-authenticate'], undefined, 'no browser password prompt may be sent')

        const me = await t2.get('/api/me')
        assert.equal(me.statusCode, 200, me.body)
        const capabilities = t2.server.body(me).capabilities
        assert.deepEqual(capabilities.auth, { mode: 'none', required: false })

        const buckets = await t2.get('/api/buckets')
        assert.equal(buckets.statusCode, 200, buckets.body)

        // writes, not just reads
        const created = await t2.server.json('POST', '/api/buckets', { name: 'open-bucket' }, { auth: false })
        assert.equal(created.statusCode, 201, created.body)
        const put = await t2.put('/api/buckets/open-bucket/objects/hello.txt', 'written without a password')
        assert.equal(put.statusCode, 201, put.body)
        const got = await t2.get('/api/buckets/open-bucket/objects/hello.txt/download')
        assert.equal(got.statusCode, 200)
        assert.equal(got.body, 'written without a password')

        // WebDAV mounts unauthenticated too
        const dav = await t2.dav('/webdav/open-bucket/')
        assert.equal(dav.statusCode, 207, dav.body)

        // and so does the S3 API (unsigned request)
        const list = await t2.get('/s3/open-bucket?list-type=2')
        assert.equal([200, 206].includes(list.statusCode), true, `${list.statusCode} ${list.body}`)

        // operations endpoints stay reachable for Prometheus/scrapers
        assert.equal((await t2.get('/metrics')).statusCode, 200)
        assert.equal((await t2.get('/healthz')).statusCode, 200)
    } finally {
        await t2.server.close()
    }
})

test('a supplied credential is still honoured, and a bad one is not fatal', async (t) => {
    const t2 = await withoutCredentials(t)
    try {
        // a correct password identifies that user
        const good = await t2.server.http.inject({
            method: 'GET', url: '/api/me', headers: { authorization: basic('admin', 'TestPassw0rd!x') },
        })
        assert.equal(good.statusCode, 200)
        assert.equal(t2.server.body(good).user.authType, 'basic')

        // a wrong password is not rejected when no password is required - it
        // falls back to open access (this is what a browser with a stale cached
        // password hits)
        const bad = await t2.server.http.inject({
            method: 'GET', url: '/api/me', headers: { authorization: basic('admin', 'not-the-password') },
        })
        assert.equal(bad.statusCode, 200, bad.body)
        assert.equal(t2.server.body(bad).user.authType, 'none')
        assert.equal(t2.server.body(bad).user.isAdmin, true)

        // access keys keep working, so SDK clients are unaffected
        const key = await createAccessKey(t2.server)
        assert.ok(key.accessKeyId && key.secretAccessKey)
        const keys = await t2.server.json('GET', '/api/admin/access-keys', undefined, { auth: false })
        assert.equal(keys.statusCode, 200)
    } finally {
        await t2.server.close()
    }
})

test('AUTH_MODE=basic puts the password back', async (t) => {
    const t2 = await createTestServer({ AUTH_MODE: 'basic' })
    try {
        const anonymous = await t2.http.inject({ method: 'GET', url: '/api/buckets' })
        assert.equal(anonymous.statusCode, 401, 'basic mode must still challenge')
        assert.match(String(anonymous.headers['www-authenticate'] || ''), /Basic/i)

        const dav = await t2.http.inject({ method: 'PROPFIND', url: '/webdav/', headers: { depth: '1' } })
        assert.equal(dav.statusCode, 401)

        const authed = await t2.json('GET', '/api/buckets')
        assert.equal(authed.statusCode, 200, authed.body)

        const me = await t2.json('GET', '/api/me')
        assert.deepEqual(t2.body(me).capabilities.auth, { mode: 'basic', required: true })
    } finally {
        await t2.close()
    }
})

test('a legacy AUTH=user:password still protects the deployment', async (t) => {
    // older configs set AUTH; the credential pair is an explicit request to be
    // asked for it, so it cannot silently become an open server
    // a legacy config: AUTH=user:password decides both the bootstrap account
    // and the credential to log in with (no explicit BOOTSTRAP_ADMIN_* set)
    const t2 = await createTestServer({
        AUTH: 'legacy:Retro-Secret1', BOOTSTRAP_ADMIN_USER: 'legacy', BOOTSTRAP_ADMIN_PASSWORD: '',
    })
    try {
        const anonymous = await t2.http.inject({ method: 'GET', url: '/api/buckets' })
        assert.equal(anonymous.statusCode, 401)
        const legacy = await t2.http.inject({
            method: 'GET', url: '/api/buckets', headers: { authorization: basic('legacy', 'Retro-Secret1') },
        })
        assert.equal(legacy.statusCode, 200, legacy.body)
    } finally {
        await t2.close()
    }
})

test('the auth mode is visible and unambiguous at boot', () => {
    // config exposes it for the boot banner and the health/summary output
    const open = loadConfig({ LOG_LEVEL: 'silent' }, { cwd: '/tmp' })
    assert.equal(open.security.authMode, 'none')
    assert.equal(open.security.authenticate, false)

    const closed = loadConfig({ AUTH_MODE: 'basic', LOG_LEVEL: 'silent' }, { cwd: '/tmp' })
    assert.equal(closed.security.authMode, 'basic')
    assert.equal(closed.security.authenticate, true)

    // aliases, and an explicit mode beating a legacy AUTH
    assert.equal(loadConfig({ DISABLE_AUTH: 'true', LOG_LEVEL: 'silent' }, { cwd: '/tmp' }).security.authMode, 'none')
    assert.equal(
        loadConfig({ AUTH: 'admin:Admin-Pass1', AUTH_MODE: 'none', LOG_LEVEL: 'silent' }, { cwd: '/tmp' }).security.authMode,
        'none',
    )
    assert.throws(() => loadConfig({ AUTH_MODE: 'banana', LOG_LEVEL: 'silent' }, { cwd: '/tmp' }), /AUTH_MODE/)
})
