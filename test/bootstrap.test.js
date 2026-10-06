/**
 * First-run bootstrap: the credentials printed on a fresh install must actually
 * work.
 *
 * The bootstrap path used to generate a random token, log it, and *then* append
 * "Aa1" when the password policy rejected the token (~10% of random draws), so
 * those installs had an administrator whose password nobody knew.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { Buffer } = require('node:buffer')

const { loadConfig } = require('../src/config')
const { createContext } = require('../src/core/context')
const { createHttpServer } = require('../src/http')
const util = require('../src/lib/util')

/** Boot a server with its own SQLite file, capturing context warnings. */
const bootInstall = async (env = {}) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ddrive-boot-'))
    const warnings = []
    const logger = {
        info: () => {}, debug: () => {}, trace: () => {}, error: () => {}, fatal: () => {},
        warn: (...args) => warnings.push(args.join(' ')),
        child() { return this },
    }
    const config = loadConfig({
        DB_DRIVER: 'sqlite',
        SQLITE_FILE: path.join(dir, 'ddrive.sqlite'),
        DATA_DIR: path.join(dir, 'data'),
        STORAGE_DRIVER: 'local',
        LOG_LEVEL: 'silent',
        PORT: '0',
        // a generated password only exists when a password is required; the
        // default (AUTH_MODE=none) never asks for one - see test/no-auth.test.js
        AUTH_MODE: 'basic',
        ...env,
    }, { cwd: dir, validate: true })
    const context = createContext(config, { logger })
    const server = createHttpServer(config, { logger: false, context })
    await context.bootstrap()
    await server.fastify.ready()

    const stop = async () => {
        await server.stop().catch(() => {})
        fs.rmSync(dir, { recursive: true, force: true })
    }

    return { server, context, config, warnings, dir, stop };
}

test('a fresh install prints a working administrator password', async () => {
    // repeat: the previous bug only affected a fraction of random draws
    for (let attempt = 0; attempt < 12; attempt += 1) {
        // eslint-disable-next-line no-await-in-loop
        const install = await bootInstall()
        try {
            const line = install.warnings.find((w) => /generated password:/.test(w))
            assert.ok(line, `no generated password was logged (${JSON.stringify(install.warnings)})`)
            const password = line.split('generated password:').pop().trim()
            assert.ok(password.length >= 8, `generated password too short: ${password}`)
            assert.equal(util.passwordPolicyError(password, 'admin'), null, `generated password violates the policy: ${password}`)

            // the logged password must be the real one
            const auth = `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`
            const login = await install.server.fastify.inject({ method: 'GET', url: '/api/admin/users', headers: { authorization: auth } })
            assert.equal(login.statusCode, 200, `attempt ${attempt}: the logged password was rejected (${login.statusCode} ${login.body})`)
        } finally {
            // eslint-disable-next-line no-await-in-loop
            await install.stop()
        }
    }
})

test('a configured bootstrap password is used verbatim', async () => {
    const password = 'FirstRun-Passw0rd'
    const install = await bootInstall({ BOOTSTRAP_ADMIN_PASSWORD: password })
    try {
        assert.equal(install.warnings.some((w) => /generated password:/.test(w)), false, 'a configured password must not be replaced')
        const auth = `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`
        const login = await install.server.fastify.inject({ method: 'GET', url: '/api/admin/users', headers: { authorization: auth } })
        assert.equal(login.statusCode, 200, `configured password rejected: ${login.statusCode} ${login.body}`)
        const user = await install.context.repo.findOne('user', { username: 'admin' })
        assert.equal(user.mustChangePassword, false, 'a configured password must not force a change')
    } finally {
        await install.stop()
    }
})

test('a weak configured bootstrap password fails fast instead of being altered', () => {
    for (const weak of ['admin', 'short1A', 'lowercase1', 'UPPERCASE1', 'NoDigitsHere']) {
        assert.throws(
            () => loadConfig({ BOOTSTRAP_ADMIN_PASSWORD: weak, DB_DRIVER: 'sqlite', LOG_LEVEL: 'silent' }, { cwd: os.tmpdir(), validate: true }),
            /BOOTSTRAP_ADMIN_PASSWORD/,
            `${weak} must be rejected at startup`,
        )
    }
})

test('the shared password policy is the one the IAM service enforces', async () => {
    // eslint-disable-next-line global-require
    const { createTestServer } = require('./helpers')
    const t = await createTestServer()
    // one case per rule: too short, no upper case, no lower case, no digit,
    // and a password that contains the username
    const rejected = [
        ['policy-probe', 'Ab1'],
        ['policy-probe', 'lowercase1'],
        ['policy-probe', 'UPPERCASE1'],
        ['policy-probe', 'NoDigitsHere'],
        ['policy-probe', 'Contains-policy-probe1'],
    ]
    try {
        for (const [username, password] of rejected) {
            assert.ok(util.passwordPolicyError(password, username), `${password} (user ${username}) should be rejected by the policy`)
            // eslint-disable-next-line no-await-in-loop
            const res = await t.json('POST', '/api/admin/users', { username, password })
            assert.equal(res.statusCode, 400, `${password} -> ${res.statusCode} ${res.body}`)
        }
        const ok = await t.json('POST', '/api/admin/users', { username: 'policy-probe', password: 'Valid-Passw0rd' })
        assert.equal(ok.statusCode, 201, ok.body)
        assert.equal(util.passwordPolicyError('Valid-Passw0rd', 'policy-probe'), null)
        // the bootstrap path uses the same rules (the username is part of them,
        // case-insensitively: "admin" or "Admin" may not appear)
        assert.ok(util.passwordPolicyError('admin', 'admin'))
        assert.ok(util.passwordPolicyError('My-Admin-Pass1', 'admin'))
        assert.equal(util.passwordPolicyError('Boot-Secret-1', 'admin'), null)
    } finally {
        await t.close()
    }
})

test('the package declares the Node version the SQLite driver needs', async () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'))
    const required = String(pkg.engines?.node || '').replace(/^[^0-9]*/, '')
    const [major, min] = required.split('.').map(Number)
    assert.ok(major >= 22, `engines.node must require Node 22+, got "${pkg.engines?.node}"`)
    if (major === 22) assert.ok(min >= 5, `node:sqlite needs 22.5+, got "${pkg.engines?.node}"`)

    // and the startup preflight must agree with it
    const entry = fs.readFileSync(path.join(__dirname, '..', 'bin', 'ddrive.js'), 'utf8')
    assert.match(entry, /REQUIRED_NODE = \[22, 5, 0\]/, 'bin/ddrive.js must fail early on an old Node with advice')
    assert.match(entry, /node:sqlite|built-in SQLite/, 'the preflight message must name the reason')
})
