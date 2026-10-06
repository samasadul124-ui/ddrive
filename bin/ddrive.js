#!/usr/bin/env node
/**
 * Start the DDrive server: `node bin/ddrive` (or `npm start`).
 *
 * Everything is configured through environment variables, see config/.env_sample
 * (loaded automatically) and docs/configuration.md.
 */
const fs = require('fs')
const path = require('path')
const dotenv = require('dotenv')

// Node prints an ExperimentalWarning for the embedded SQLite driver on every
// boot. It is not actionable here (SQLite is the zero-dependency default, and
// the alternative is running Postgres), so it is filtered out of the startup
// output - every other warning is still printed exactly as Node produced it.
process.removeAllListeners('warning')
process.on('warning', (warning) => {
    if (warning.name === 'ExperimentalWarning' && /SQLite/i.test(warning.message || '')) return
    // eslint-disable-next-line no-console
    console.warn(`${warning.name}: ${warning.message}`)
})

/**
 * The zero-dependency SQLite driver is Node's own `node:sqlite` (>= 22.5). On an
 * older runtime that shows up as a stack trace deep inside the driver, so say it
 * plainly before anything else is loaded.
 */
const REQUIRED_NODE = [22, 5, 0]
const nodeVersionOk = () => {
    const [major, minor] = process.versions.node.split('.').map(Number)
    if (major > REQUIRED_NODE[0]) return true
    if (major === REQUIRED_NODE[0] && minor >= REQUIRED_NODE[1]) return true

    return false
}
if (!nodeVersionOk() && String(process.env.DB_DRIVER || 'sqlite') === 'sqlite') {
    /* eslint-disable no-console */
    console.error(`[ddrive] Node.js ${REQUIRED_NODE.join('.')} or newer is required (you have ${process.versions.node}).`)
    console.error('[ddrive] The default database driver uses Node\'s built-in SQLite. Install a current Node from https://nodejs.org and run this command again.')
    console.error('[ddrive] (Alternatively set DB_DRIVER=postgres with a Postgres server - not needed on a laptop.)')
    /* eslint-enable no-console */
    process.exit(1)
}

const { loadConfig } = require('../src/config')
const { createHttpServer } = require('../src')
const { humanBytes } = require('../src/lib/limits')

/**
 * One line that answers "where does my data actually go?" - the question behind
 * most "my upload does not reach Discord" reports. The chunk size is shown
 * because a chunk bigger than the backend accepts is rejected outright.
 */
const storageSummary = (config) => {
    const s = config.storage
    const tiers = [s.cool, s.archive].filter(Boolean).map((t) => t.driver || s.driver)
    const parts = [
        `storage=${s.driver}`,
        `chunk=${humanBytes(s.chunkSize)}`,
        `data=${s.driver === 'discord' ? `${s.webhooks.length} webhook(s)` : s.directory}`,
        `db=${config.database.driver}`,
        `auth=${config.security.authMode}`,
    ]
    if (tiers.length) parts.push(`tiers=${tiers.join(',')}`)

    return parts.join(' ')
}

const envFile = process.env.ENV_FILE || path.join(process.cwd(), 'config', '.env')
if (fs.existsSync(envFile)) dotenv.config({ path: envFile })

const main = async () => {
    const config = loadConfig(process.env, { cwd: process.cwd(), validate: true })
    const server = createHttpServer(config)

    // before the listener, so the operator sees it even if a proxy swallows logs
    // eslint-disable-next-line no-console
    console.log(`[ddrive] ${storageSummary(config)}`)
    if (config.storage.chunkSizeAdjustment) {
        const adj = config.storage.chunkSizeAdjustment
        // eslint-disable-next-line no-console
        console.warn(`[ddrive] CHUNK_SIZE=${adj.requested} is larger than the ${humanBytes(adj.limit)} limit of the `
            + `${adj.drivers.join('/')} backend; using ${humanBytes(adj.applied)}. `
            + 'Uploads larger than the limit are rejected by the backend.')
    }
    if (config.security.authenticate) {
        // eslint-disable-next-line no-console
        console.log('[ddrive] authentication is ON: the panel, WebDAV and S3 require credentials '
            + `(AUTH_MODE=basic, user "${config.security.bootstrap.username}")`)
    } else {
        // eslint-disable-next-line no-console
        console.warn('[ddrive] AUTHENTICATION IS DISABLED: anyone who can reach this port has full access '
            + 'to every bucket, object and setting. If this machine is reachable from the internet, '
            + 'set AUTH_MODE=basic and a password, or bind HOST=127.0.0.1 and use a firewall.')
    }
    if (config.storage.driver === 'discord') {
        // eslint-disable-next-line no-console
        console.log(`[ddrive] files will be stored in Discord via ${config.storage.webhooks.length} webhook(s); `
            + 'the panel lists them from the database, so keep the database.')
    }

    await server.start()

    const { port, host } = config.servers
    const display = host === '0.0.0.0' || host === '::' ? 'localhost' : host
    const where = `http://${display}:${port}`
    // eslint-disable-next-line no-console
    console.log('')
    // eslint-disable-next-line no-console
    console.log(`[ddrive] Ready. Open ${where} in your browser and drop a file on the page.`)
    // eslint-disable-next-line no-console
    console.log(`[ddrive] WebDAV: ${where}/webdav   S3 API: ${where}/s3   Stop: Ctrl+C`)
    // eslint-disable-next-line no-console
    console.log('')

    const shutdown = async (signal) => {
        server.fastify.log.info(`received ${signal}, shutting down`)
        try {
            await server.stop()
        } finally {
            process.exit(0)
        }
    }
    process.on('SIGINT', () => { shutdown('SIGINT') })
    process.on('SIGTERM', () => { shutdown('SIGTERM') })
    process.on('unhandledRejection', (err) => {
        server.fastify.log.error({ err }, 'unhandled rejection')
    })

    return server
}

main().catch((err) => {
    // eslint-disable-next-line no-console
    console.error(`Failed to start DDrive: ${err.message}`)
    process.exit(1)
})
