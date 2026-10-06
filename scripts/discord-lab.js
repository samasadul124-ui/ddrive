#!/usr/bin/env node
/**
 * One-command local lab: starts DDrive with the Discord chunk backend and
 * prints everything you need (URLs, credentials, how to connect).
 *
 *   npm run discord:lab
 *
 * Reads WEBHOOKS from config/.env (or the environment). Everything else is
 * defaulted for local use, so there is nothing to configure:
 *
 *   - SQLite database under ./lab/    (no Postgres needed)
 *   - admin / ddrive-lab-2026 password
 *   - S3 on /s3, WebDAV on /webdav, console on /console/
 *
 * Override anything with env vars, e.g.
 *   PORT=8080 npm run discord:lab
 */
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const root = path.join(__dirname, '..')
require('dotenv').config({ path: path.join(root, 'config', '.env') })

const labDir = process.env.LAB_DIR || path.join(root, 'lab')
fs.mkdirSync(labDir, { recursive: true })

const webhooks = String(process.env.WEBHOOKS || process.env.WEBHOOK_FILE || '')
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter(Boolean)

if (!webhooks.length) {
    console.error(`
No Discord webhooks configured.

  Add them to config/.env (gitignored):

      WEBHOOKS=https://discord.com/api/webhooks/<id>/<token>,https://discord.com/api/webhooks/<id>/<token>

  or pass them inline:

      WEBHOOKS="https://discord.com/api/webhooks/..." npm run discord:lab

Create webhooks in Discord: Channel settings -> Integrations -> Webhooks -> New Webhook.
Use a throwaway channel - DDrive writes one attachment per chunk into it.
`)
    process.exit(2)
}

const mask = (url) => url.replace(/(webhooks\/\d+\/)[\w-]+/, '$1***')
console.log(`\nDDrive lab - ${webhooks.length} Discord webhook(s)`)
webhooks.forEach((url, index) => console.log(`  [${index + 1}] ${mask(url)}`))

const password = process.env.LAB_PASSWORD || 'ddrive-lab-2026'
const port = Number(process.env.PORT || 3000)
const env = {
    ...process.env,

    // Discord chunk storage
    STORAGE_DRIVER: 'discord',
    WEBHOOKS: webhooks.join(','),
    // stay under Discord's 25 MiB attachment limit with headroom for the
    // per-chunk encryption envelope and multipart overhead
    CHUNK_SIZE: process.env.CHUNK_SIZE || String(8 * 1024 * 1024),

    // embedded database + object metadata
    DB_DRIVER: 'sqlite',
    SQLITE_FILE: path.join(labDir, 'ddrive.sqlite'),
    DATA_DIR: path.join(labDir, 'data'),

    // encryption: a stable local master key so restarts can still read data
    MASTER_KEY: process.env.MASTER_KEY || 'ddrive-lab-master-key',
    SECRET: process.env.SECRET || 'ddrive-lab-legacy-secret',

    // credentials + transport
    BOOTSTRAP_ADMIN_PASSWORD: password,
    AUTH: `admin:${password}`,
    PORT: String(port),
    HOST: process.env.HOST || '0.0.0.0',
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',

    // keep the audit trail next to the data
    AUDIT_LOG_FILE: process.env.AUDIT_LOG_FILE || path.join(labDir, 'audit.jsonl'),
}
Object.assign(process.env, env)

const { loadConfig } = require('../src/config')
const { createHttpServer } = require('../src')

const main = async () => {
    const config = loadConfig(process.env, { cwd: root })
    const server = createHttpServer(config)
    await server.start()

    const base = `http://localhost:${port}`
    console.log(`
  ready

    console    ${base}/console/          (admin / ${password})
    S3 API     ${base}/s3
    WebDAV     ${base}/webdav            mount this as a network drive
    REST API   ${base}/api
    health     ${base}/healthz

  WebDAV mount (Finder / Explorer / rclone):

    ${base}/webdav          user: admin   password: ${password}

  rclone example:

    rclone config create ddrive webdav url=${base}/webdav vendor=other user=admin pass=<password>

  Data lives in ${labDir}
  Press Ctrl+C to stop.
`)

    const shutdown = async (signal) => {
        console.log(`\nreceived ${signal}, stopping...`)
        try {
            await server.stop()
        } finally {
            process.exit(0)
        }
    }
    process.on('SIGINT', () => shutdown('SIGINT'))
    process.on('SIGTERM', () => shutdown('SIGTERM'))

    return server
}

main().catch((err) => {
    console.error(`\nFailed to start the lab: ${err.message}\n`)
    process.exit(1)
})

// keep a reference so the process is not garbage collected
void crypto
