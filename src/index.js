/**
 * DDrive: a self hosted, S3 compatible, WebDAV mountable cloud storage system.
 *
 * Programmatic use:
 *   const { createContext, createHttpServer } = require('@forscht/ddrive')
 *   const server = createHttpServer(loadConfig(process.env))
 *   await server.start()
 */
const { DFs } = require('./DFs')
const { loadConfig } = require('./config')
const { createContext, VERSION } = require('./core/context')
const { createHttpServer } = require('./http')

/**
 * Legacy (v4) factory: `HttpServer(dfs, {DFsConfig, httpConfig})`.
 * It returns a ready-to-listen fastify instance bootstrapped from the
 * environment, reusing the Discord webhooks/chunk size of a v4 DFs instance if
 * one is passed in.
 */
const HttpServer = (dfs, opts = {}) => {
    const config = loadConfig(process.env, { cwd: process.cwd() })
    const webhooks = (dfs && dfs.webhooks) || (opts.DFsConfig && opts.DFsConfig.webhooks)
    if (webhooks && webhooks.length) {
        config.storage.driver = 'discord'
        config.storage.webhooks = webhooks
    }
    if (opts.DFsConfig?.chunkSize) config.storage.chunkSize = opts.DFsConfig.chunkSize
    if (opts.DFsConfig?.maxConcurrency) config.storage.concurrency = opts.DFsConfig.maxConcurrency
    if (opts.httpConfig?.port) config.servers.port = opts.httpConfig.port

    return createHttpServer(config).fastify
}

module.exports = {
    DFs,
    HttpServer,
    createContext,
    createHttpServer,
    loadConfig,
    VERSION,
}
