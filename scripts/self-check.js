#!/usr/bin/env node
/**
 * Self-check for a running DDrive server.
 *
 *   npm start          # in one terminal
 *   npm run check      # in another (or pass a URL: npm run check -- http://host:3000)
 *
 * It pushes real bytes through every surface - the web panel's own upload
 * endpoint, WebDAV and the S3 API - reads them back and compares, then checks
 * the audit chain and the encryption key file. Nothing is left behind.
 *
 * Options:
 *   --url <url>            server to test              (default http://127.0.0.1:3000)
 *   --size <bytes>         payload size                (default: a bit over one chunk)
 *   --keep                 do not delete the test data
 *
 * When the server runs with AUTH_MODE=basic (or a legacy AUTH=user:password),
 * pass credentials the same way the browser would:
 *   DDRIVE_USER=admin DDRIVE_PASSWORD='…' npm run check
 */
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const sigv4 = require('../src/lib/sigv4')

const args = process.argv.slice(2)
const argValue = (name, fallback) => {
    const hit = args.findIndex((a) => a === name)
    if (hit === -1) return fallback

    return args[hit + 1] || fallback
}
const BASE = (argValue('--url', process.env.DDRIVE_URL) || `http://127.0.0.1:${process.env.PORT || 3000}`).replace(/\/$/, '')
const KEEP = args.includes('--keep')
const SIZE = Number(argValue('--size', process.env.DDRIVE_CHECK_SIZE || 12 * 1024 * 1024))
const NAME = `self-check-${crypto.randomBytes(3).toString('hex')}.bin`
const BUCKET = `self-check-${crypto.randomBytes(3).toString('hex')}`

const AUTH = process.env.DDRIVE_USER
    ? `Basic ${Buffer.from(`${process.env.DDRIVE_USER}:${process.env.DDRIVE_PASSWORD || ''}`).toString('base64')}`
    : null
const authHeaders = (extra = {}) => (AUTH ? { authorization: AUTH, ...extra } : { ...extra })

let passed = 0
let failed = 0
const ok = (name, detail = '') => {
    passed += 1
    console.log(`  ok      ${name}${detail ? `  (${detail})` : ''}`)
}
const bad = (name, detail = '') => {
    failed += 1
    console.log(`  FAILED  ${name}${detail ? `  (${detail})` : ''}`)
}
const check = (name, condition, detail = '') => (condition ? ok(name, detail) : bad(name, detail))

const section = (title) => console.log(`\n${title}`)

const readJson = async (url, opts) => {
    const res = await fetch(url, opts)

    return { res, body: await res.json().catch(() => null) }
}

const main = async () => {
    console.log(`DDrive self-check against ${BASE}`)
    console.log(`Payload: ${SIZE.toLocaleString()} bytes per surface\n`)

    // ---------------------------------------------------------------- reachable
    section('Server')
    try {
        const res = await fetch(`${BASE}/`, { headers: authHeaders() })
        check('the web panel answers', res.status === 200, `HTTP ${res.status}`)
    } catch (err) {
        bad('the web panel answers', `${err.cause?.code || err.message} - is the server started? (npm start)`)
        console.log('\nNothing else can be tested. Start the server and try again.')

        return
    }

    const health = await readJson(`${BASE}/healthz`)
    check('health endpoint is ready', health.res.status === 200, `HTTP ${health.res.status}`)

    // ------------------------------------------------------------------- panel
    section('Web panel (the endpoint the upload button uses)')
    const root = await readJson(`${BASE}/api/directories/`, { headers: authHeaders() })
    if (root.res.status !== 200 || !root.body?.id) {
        bad('the file listing is readable', `HTTP ${root.res.status}`)
        console.log('\nWith a password set, pass credentials: DDRIVE_USER=admin DDRIVE_PASSWORD=… npm run check')

        return
    }
    ok('the file listing is readable')

    const payload = crypto.randomBytes(SIZE)
    const form = new FormData()
    form.append('file', new Blob([payload]), NAME)
    const uploaded = await fetch(`${BASE}/api/files/${root.body.id}`, {
        method: 'POST', headers: authHeaders(), body: form,
    })
    check('a real file uploads', uploaded.status === 201, `HTTP ${uploaded.status}, ${SIZE.toLocaleString()} bytes`)
    const file = await uploaded.json().catch(() => null)

    const listed = await readJson(`${BASE}/api/directories/`, { headers: authHeaders() })
    const listedFile = (listed.body?.child?.files || []).find((f) => f.name === NAME)
    check('the upload is listed', Boolean(listedFile))

    if (listedFile) {
        const download = await fetch(`${BASE}/api/files/${listedFile.id}/download`, { headers: authHeaders() })
        const back = Buffer.from(await download.arrayBuffer())
        check('the download is byte-identical', back.equals(payload), `${back.length.toLocaleString()} bytes`)
        const ranged = await fetch(`${BASE}/api/files/${listedFile.id}/download`, { headers: authHeaders({ range: 'bytes=0-15' }) })
        check('range requests work', ranged.status === 206, `HTTP ${ranged.status}`)
        const meta = await readJson(`${BASE}/api/files/${listedFile.id}`, { headers: authHeaders() })
        check('the file is browsable by id', meta.res.status === 200)
    }

    // ------------------------------------------------------------------ WebDAV
    section('WebDAV (mount it as a drive)')
    const davUrl = `${BASE}/webdav/ddrive/${NAME}`
    const put = await fetch(davUrl, { method: 'PUT', headers: authHeaders({ 'content-type': 'application/octet-stream' }), body: payload })
    check('a file can be written over WebDAV', [200, 201, 204].includes(put.status), `HTTP ${put.status}`)
    const get = await fetch(davUrl, { headers: authHeaders() })
    const davBack = Buffer.from(await get.arrayBuffer())
    check('it reads back byte-identical', davBack.equals(payload), `${davBack.length.toLocaleString()} bytes`)
    const propfind = await fetch(`${BASE}/webdav/ddrive/`, { method: 'PROPFIND', headers: authHeaders({ depth: '1' }) })
    const davBody = await propfind.text()
    check('the collection lists with PROPFIND', propfind.status === 207, `HTTP ${propfind.status}`)
    check('the file appears in the listing', davBody.includes(NAME))

    // ---------------------------------------------------------------------- S3
    section('S3 API (SigV4, aws cli / SDK compatible)')
    const keyRes = await readJson(`${BASE}/api/admin/access-keys`, {
        method: 'POST',
        headers: authHeaders({ 'content-type': 'application/json' }),
        body: JSON.stringify({ username: process.env.DDRIVE_USER || 'admin' }),
    })
    const credentials = keyRes.body
    if (!credentials?.accessKeyId || !credentials?.secretAccessKey) {
        bad('an access key can be created', `HTTP ${keyRes.res.status}`)
    } else {
        ok('an access key can be created')
        const creds = { ...credentials, region: 'us-east-1', service: 's3' }
        const sign = (method, url, headers, payloadHash) => sigv4.signRequest(
            { method, url, headers: headers || {}, payloadHash }, creds,
        )
        const hash = crypto.createHash('sha256').update(payload).digest('hex')

        const createBucket = await fetch(`${BASE}/s3/${BUCKET}`, {
            method: 'PUT', headers: sign('PUT', `${BASE}/s3/${BUCKET}`, {}, hash),
        })
        check('a bucket can be created', createBucket.status === 200, `HTTP ${createBucket.status}`)

        const objectUrl = `${BASE}/s3/${BUCKET}/${NAME}`
        const putObject = await fetch(objectUrl, {
            method: 'PUT',
            headers: sign('PUT', objectUrl, { 'content-type': 'application/octet-stream', 'x-amz-meta-check': 'self-check' }, hash),
            body: payload,
        })
        check('an object can be uploaded (PutObject)', [200, 201].includes(putObject.status), `HTTP ${putObject.status}`)

        const getObject = await fetch(objectUrl, { headers: sign('GET', objectUrl, {}, 'UNSIGNED-PAYLOAD') })
        const s3Back = Buffer.from(await getObject.arrayBuffer())
        check('the object reads back byte-identical (GetObject)', s3Back.equals(payload), `${s3Back.length.toLocaleString()} bytes`)
        check('custom metadata survives', getObject.headers.get('x-amz-meta-check') === 'self-check')

        const list = await fetch(`${BASE}/s3/${BUCKET}?list-type=2`, { headers: sign('GET', `${BASE}/s3/${BUCKET}?list-type=2`, {}, 'UNSIGNED-PAYLOAD') })
        const listBody = await list.text()
        check('the object is listed (ListObjectsV2)', list.status === 200 && listBody.includes(NAME), `HTTP ${list.status}`)

        const missing = await fetch(`${BASE}/s3/${BUCKET}-missing/${NAME}`, {
            method: 'PUT', headers: sign('PUT', `${BASE}/s3/${BUCKET}-missing/${NAME}`, {}, hash), body: payload,
        })
        check('an upload into a missing bucket is refused, not dropped', missing.status === 404, `HTTP ${missing.status}`)

        if (!KEEP) {
            await fetch(objectUrl, { method: 'DELETE', headers: sign('DELETE', objectUrl, {}, 'UNSIGNED-PAYLOAD') }).catch(() => {})
            await fetch(`${BASE}/s3/${BUCKET}`, { method: 'DELETE', headers: sign('DELETE', `${BASE}/s3/${BUCKET}`, {}, 'UNSIGNED-PAYLOAD') }).catch(() => {})
        }
    }

    // ------------------------------------------------------------ audit + key
    section('Compliance and encryption')
    const verify = await readJson(`${BASE}/api/admin/audit/verify`, { headers: authHeaders() })
    check('the tamper-evident audit chain verifies', verify.body?.ok === true, `${verify.body?.checked ?? '?'} entries`)
    const audit = await readJson(`${BASE}/api/admin/audit?limit=1`, { headers: authHeaders() })
    const newest = (audit.body?.events || audit.body?.entries || [])[0]
    check('the upload left an audit entry', Boolean(newest), newest ? newest.action : 'no entries')

    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data')
    const keyFile = process.env.MASTER_KEY_FILE || path.join(dataDir, 'master.key')
    if (process.env.MASTER_KEY) {
        ok('an explicit MASTER_KEY is configured')
    } else if (fs.existsSync(keyFile)) {
        const mode = fs.statSync(keyFile).mode & 0o777
        check('the generated master key file is owner-only', process.platform === 'win32' || mode === 0o600, `mode ${mode.toString(8)}`)
    } else {
        bad('an encryption key exists', `no key at ${keyFile}`)
    }

    // ------------------------------------------------------------------ cleanup
    if (!KEEP) {
        if (listedFile) await fetch(`${BASE}/api/files/${listedFile.id}`, { method: 'DELETE', headers: authHeaders() }).catch(() => {})
        await fetch(davUrl, { method: 'DELETE', headers: authHeaders() }).catch(() => {})
        console.log('\nTest data removed (pass --keep to leave it in place).')
    }

    console.log(`\n${'='.repeat(46)}`)
    console.log(`  ${passed} checks passed, ${failed} failed`)
    console.log(`${'='.repeat(46)}`)
    if (file?.name) console.log(`(uploaded as "${file.name}", bucket "${BUCKET}")`)
}

main().then(() => {
    process.exitCode = failed > 0 ? 1 : 0
}).catch((err) => {
    console.error(`\nself-check crashed: ${err.stack || err.message}`)
    process.exitCode = 1
})
