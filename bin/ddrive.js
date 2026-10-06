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
