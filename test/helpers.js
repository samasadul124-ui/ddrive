/**
 * Test harness: boots the whole platform in-process (embedded SQLite + local
 * object store + temporary data dir) so the suite needs no network and no
 * external services. Fastify's `inject()` is used instead of real sockets.
 */
const fs = require('fs')
const os = require('os')
const path = require('path')
const { Buffer } = require('buffer')

const { loadConfig } = require('../src/config')
const { createHttpServer } = require('../src/http')
const sigv4 = require('../src/lib/sigv4')

const ADMIN = { username: 'admin', password: 'TestPassw0rd!x' }

const baseEnv = (dir) => ({
    DB_DRIVER: 'sqlite',
    SQLITE_FILE: path.join(dir, 'ddrive.sqlite'),
    STORAGE_DRIVER: 'local',
    DATA_DIR: path.join(dir, 'data'),
    MASTER_KEY: 'test-master-key',
    BOOTSTRAP_ADMIN_USER: ADMIN.username,
    BOOTSTRAP_ADMIN_PASSWORD: ADMIN.password,
    LOG_LEVEL: 'silent',
    PORT: '0',
})

/** Boot a fresh server. Returns helpers bound to that instance. */
const createTestServer = async (extraEnv = {}) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ddrive-test-'))
    fs.mkdirSync(path.join(dir, 'data'), { recursive: true })
    const config = loadConfig({ ...baseEnv(dir), ...extraEnv }, { cwd: dir })
    const server = createHttpServer(config, { logger: false })
    await server.fastify.ready()

    const basic = `Basic ${Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString('base64')}`

    /** Inject a REST/WebDAV request with the admin basic credentials. */
    const authed = (opts) => server.fastify.inject({
        ...opts,
        headers: { authorization: basic, ...(opts.headers || {}) },
    })

    /** Inject a JSON request (admin auth by default). */
    const json = (method, url, body, opts = {}) => {
        const headers = { 'content-type': 'application/json', ...(opts.headers || {}) }
        if (opts.auth !== false) headers.authorization = basic

        return server.fastify.inject({
            method, url, headers, payload: body === undefined ? undefined : JSON.stringify(body),
        })
    }

    /** Parse a JSON body from an inject response. */
    const body = (res) => JSON.parse(res.body)

    const close = async () => {
        await server.stop().catch(() => {})
        fs.rmSync(dir, { recursive: true, force: true })
    }

    return {
        dir, config, server, context: server.context, http: server.fastify, authed, json, body, close, basic,
    }
}

/** Create an access key pair for the bootstrap admin. */
const createAccessKey = async (t) => {
    const res = await t.json('POST', '/api/admin/access-keys', { username: ADMIN.username, description: 'test' })
    if (res.statusCode !== 201) throw new Error(`access key creation failed: ${res.statusCode} ${res.body}`)

    return t.body(res)
}

/**
 * Sign + inject an S3 request against the /s3 mount, using the platform's own
 * SigV4 implementation (interop with the official AWS SDK signer is covered by
 * the external harness in /home/user/s3test).
 */
const s3 = async (t, opts = {}) => {
    const crypto = require('crypto')
    const credentials = opts.credentials || t.credentials
    const payload = opts.payload === undefined ? Buffer.alloc(0) : Buffer.from(opts.payload)
    const query = opts.query ? `?${new URLSearchParams(opts.query)}` : ''
    const target = `/s3${opts.path}${query}`
    const url = `http://127.0.0.1:3111${target}`
    const payloadHash = crypto.createHash('sha256').update(payload).digest('hex')
    const headers = sigv4.signRequest({
        method: opts.method || 'GET', url, headers: opts.headers || {}, payloadHash,
    }, { ...credentials, region: 'us-east-1', service: 's3' })

    return t.http.inject({
        method: opts.method || 'GET', url: target, headers, payload,
    })
}

module.exports = {
    ADMIN, createTestServer, createAccessKey, s3,
}
