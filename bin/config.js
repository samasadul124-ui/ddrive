/**
 * Legacy configuration adapter: v4 `bin/config.js` returned
 * `{httpConfig, DFsConfig}`. DDrive v5 uses `loadConfig()` from `src/config`,
 * but this shim keeps old deployment scripts working.
 */
const { loadConfig, VALID_PUBLIC_ACCESS } = require('../src/config')

module.exports = () => {
    const config = loadConfig(process.env, { cwd: process.cwd() })

    return {
        httpConfig: {
            port: config.servers.port,
            authOpts: {
                auth: {
                    user: config.security.bootstrap.username,
                    pass: config.security.bootstrap.password,
                },
                publicAccess: config.security.publicAccess,
            },
            publicAccess: config.security.publicAccess,
        },
        DFsConfig: {
            chunkSize: config.storage.chunkSize,
            webhooks: config.storage.webhooks,
            secret: config.security.legacySecret,
            maxConcurrency: config.storage.concurrency,
            restOpts: { timeout: config.servers.requestTimeout },
        },
        config,
        VALID_PUBLIC_ACCESS,
    }
}
