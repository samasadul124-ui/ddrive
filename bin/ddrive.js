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

const envFile = process.env.ENV_FILE || path.join(process.cwd(), 'config', '.env')
if (fs.existsSync(envFile)) dotenv.config({ path: envFile })

const main = async () => {
    const config = loadConfig(process.env, { cwd: process.cwd(), validate: true })
    const server = createHttpServer(config)
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
