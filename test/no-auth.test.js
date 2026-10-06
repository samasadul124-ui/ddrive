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

test('a fresh install with no MASTER_KEY still encrypts secrets at rest', async (t) => {
    // regression: creating an access key returned HTTP 500 ("No encryption key
    // provider configured") because access key secrets are encrypted at rest and
    // a default install has no key material. A local key is now generated once.
    const t2 = await createTestServer({ MASTER_KEY: '', MASTER_KEY_FILE: '' })
    try {
        const keyFile = require('path').join(t2.dir, 'data', 'master.key')

        const created = await t2.json('POST', '/api/admin/access-keys', { username: 'admin', description: 'no-master-key' })
        assert.equal(created.statusCode, 201, created.body)
        const key = t2.body(created)
        assert.ok(key.accessKeyId && key.secretAccessKey)

        // the secret is encrypted at rest, not stored in the clear
        const row = await t2.context.repo.findOne('access_key', { accessKeyId: key.accessKeyId })
        assert.ok(row.secretEnc && !String(row.secretEnc).includes(key.secretAccessKey), 'the secret must be encrypted at rest')
        assert.ok(row.iv && row.authTag, 'the encrypted secret needs its iv and tag')

        // a generated key file exists, is private, and is stable across restarts
        const fs = require('node:fs')
        assert.ok(fs.existsSync(keyFile), `expected a generated key at ${keyFile}`)
        assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600, 'the key file must not be world readable')
        const material = fs.readFileSync(keyFile, 'utf8').trim()
        assert.match(material, /^[0-9a-f]{64}$/)

        // rounding trip through the API proves the key decrypts what it encrypted
        const listed = await t2.json('GET', '/api/admin/access-keys')
        assert.equal(listed.statusCode, 200)
        assert.ok(t2.body(listed).keys.some((k) => k.accessKeyId === key.accessKeyId))
        const resolved = await t2.context.iam.resolveAccessKey(key.accessKeyId)
        assert.equal(resolved.secretAccessKey, key.secretAccessKey, 'the stored secret must decrypt to the issued one')

        // object bytes are encrypted too (encryption is on by default now)
        const bucket = await t2.json('POST', '/api/buckets', { name: 'enc-default' })
        assert.equal(bucket.statusCode, 201, bucket.body)
        const put = await t2.http.inject({
            method: 'PUT',
            url: '/api/buckets/enc-default/objects/secret.txt',
            headers: { authorization: t2.basic, 'content-type': 'text/plain' },
            payload: 'this should be encrypted at rest',
        })
        assert.equal(put.statusCode, 201, put.body)
        const node = await t2.context.objects.getNode((await t2.context.buckets.get('enc-default')).id, 'secret.txt')
        const version = await t2.context.repo.findOne('object_version', { id: node.latestVersionId })
        assert.ok(version.wrappedDek, 'the chunk DEK must be wrapped by the local key')
        const stored = require('node:fs').readdirSync(require('path').join(t2.dir, 'data', 'chunks'), { recursive: true })
        const chunkFile = stored.map((f) => require('path').join(t2.dir, 'data', 'chunks', f)).find((f) => require('node:fs').statSync(f).isFile())
        const raw = require('node:fs').readFileSync(chunkFile)
        assert.equal(raw.includes(Buffer.from('this should be encrypted at rest')), false, 'the chunk must not contain the plaintext')

        // and it reads back correctly
        const got = await t2.http.inject({
            method: 'GET', url: '/api/buckets/enc-default/objects/secret.txt/download', headers: { authorization: t2.basic },
        })
        assert.equal(got.statusCode, 200)
        assert.equal(got.body, 'this should be encrypted at rest')
    } finally {
        await t2.close()
    }
})

test('an explicit MASTER_KEY wins, and production never auto-generates', async (t) => {
    const t2 = await createTestServer({ MASTER_KEY: 'explicit-master-key-for-tests' })
    try {
        const created = await t2.json('POST', '/api/admin/access-keys', { username: 'admin', description: 'explicit' })
        assert.equal(created.statusCode, 201, created.body)
        assert.equal(t2.context.crypto.provider.type, 'local')
        assert.equal(t2.context.crypto.provider.autoGenerated, false)
        // nothing was written to disk behind the operator's back
        assert.equal(require('node:fs').existsSync(require('path').join(t2.dir, 'data', 'master.key')), false)
    } finally {
        await t2.close()
    }

    // production requires an explicit key: missing one is a config error, not an
    // invitation to invent a key on a server nobody will back up
    assert.throws(
        () => loadConfig({ NODE_ENV: 'production', LOG_LEVEL: 'silent' }, { cwd: '/tmp', validate: true }),
        /MASTER_KEY/,
    )
    const auto = loadConfig({ LOG_LEVEL: 'silent' }, { cwd: '/tmp' })
    assert.equal(auto.security.autoGenerateMasterKey, true)
    const explicitOff = loadConfig({ MASTER_KEY_AUTOGENERATE: 'false', LOG_LEVEL: 'silent' }, { cwd: '/tmp' })
    assert.equal(explicitOff.security.autoGenerateMasterKey, false)
})
