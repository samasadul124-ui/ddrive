/**
 * Application context: dependency injection + bootstrap for the whole system.
 *
 * Everything the servers need is created here exactly once:
 *   database -> repository -> (buckets, objects, iam, audit, events, ...)
 *
 * `createContext()` is pure wiring; `context.bootstrap()` creates the schema,
 * seeds the built-in policies/roles, the default bucket and the first
 * administrator, and (optionally) starts the background workers.
 */
const { createDb, ensureSchema, schemaSql, migrationsDir } = require('../db')
const { Repository } = require('./repository')
const { createChunkStore } = require('./storage')
const { CryptoBox, createKeyProvider } = require('./crypto')
const { createAudit } = require('./audit')
const { createEvents } = require('./events')
const { createMetrics } = require('./metrics')
const { createIam } = require('./iam')
const { createBuckets } = require('./buckets')
const { Objects } = require('./objects')
const { createShares } = require('./shares')
const { createTagger } = require('./tagger')
const { createLifecycle } = require('./lifecycle')
const { createTiering } = require('./tiering')
const { createReplication } = require('./replication')
const util = require('../lib/util')

const VERSION = require('../../package.json').version

const createContext = (config, opts = {}) => {
    const logger = opts.logger || console
    const db = createDb({
        driver: config.database.driver,
        databaseUrl: config.database.url,
        sqliteFile: config.database.sqliteFile,
        pool: config.database.pool,
        busyTimeout: config.database.busyTimeout,
    })
    const repo = new Repository(db)

    const store = createChunkStore({
        driver: config.storage.driver,
        chunkSize: config.storage.chunkSize,
        concurrency: config.storage.concurrency,
        local: { directory: config.storage.directory },
        discord: {
            webhooks: config.storage.webhooks,
            apiBase: config.storage.discordApiBase,
            timeout: config.servers.requestTimeout,
            concurrency: config.storage.concurrency,
        },
        cool: config.storage.cool,
        archive: config.storage.archive,
    })

    const provider = createKeyProvider({
        masterKey: config.security.masterKey,
        masterKeyFile: config.security.masterKeyFile,
        kmsEndpoint: config.security.kmsEndpoint,
        kmsToken: config.security.kmsToken,
        kmsKeyId: config.security.kmsKeyId,
        kmsProvider: config.security.kmsProvider,
    })
    const crypto = new CryptoBox({
        provider,
        algorithm: config.security.algorithm,
        legacySecret: config.security.legacySecret,
    })

    const metrics = createMetrics({ logger })
    const audit = createAudit({
        repo,
        logger,
        file: config.audit.file,
        webhookUrl: config.audit.webhookUrl,
        syslogHost: config.audit.syslogHost,
        syslogPort: config.audit.syslogPort,
        retentionDays: config.audit.retentionDays,
    })
    const events = createEvents({
        repo,
        logger,
        metrics,
        intervalMs: config.workers.eventsIntervalMs,
        maxRetriesDefault: 5,
    })
    const iam = createIam({
        repo, crypto, audit, logger,
    })
    const objects = new Objects({
        repo,
        store,
        crypto,
        events,
        audit,
        logger,
        metrics,
        config: {
            chunkSize: config.storage.chunkSize,
            multipartTtlDays: config.workers.multipartTtlDays,
        },
        tagger: null,
    })
    // buckets depend on objects (recursive delete) - wired right after creation
    const buckets = createBuckets({
        repo, objects, crypto, events, logger,
    })
    objects.buckets = buckets
    const tagger = createTagger({
        repo, objects, audit, events, logger, aiUrl: config.ai.url, aiToken: config.ai.token, aiMinConfidence: config.ai.minConfidence, aiTimeoutMs: config.ai.timeoutMs,
    })
    objects.tagger = tagger
    objects.deps = { tagger, events }

    const tiering = createTiering({
        repo, store, objects, events, audit, logger,
    })
    const lifecycle = createLifecycle({
        repo, objects, events, audit, tagger, tiering, logger,
    })
    const replication = createReplication({
        repo,
        objects,
        store,
        events,
        audit,
        crypto,
        buckets,
        logger,
        config: {
            region: config.node.region,
            nodeId: config.node.name,
            maxAttempts: config.workers.replicationMaxAttempts,
            timeoutMs: config.servers.requestTimeout,
            batchSize: 10,
        },
    })
    const shares = createShares({
        repo, objects, crypto, audit,
    })

    const timers = []
    let bootstrapped = false

    const seed = async () => {
        await iam.seedBuiltinPolicies()
        await iam.seedBuiltinRoles()

        // first administrator
        const users = await repo.count('user')
        if (!users) {
            const password = config.security.bootstrap.password || util.randomToken(12)
            const user = await iam.createUser({
                username: config.security.bootstrap.username,
                password: password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password)
                    ? password
                    : `${password}Aa1`,
                isAdmin: true,
                displayName: 'Administrator',
                mustChangePassword: !config.security.bootstrap.password,
            })
            await iam.setUserRoles(user.id, ['Administrators'])
            if (!config.security.bootstrap.password) {
                logger.warn?.(`Created administrator "${user.username}" with generated password: ${password}`)
                logger.warn?.('Set BOOTSTRAP_ADMIN_PASSWORD to control this password, then change it in the console.')
            }
        }

        // default bucket
        let bucket = await repo.findOne('bucket', { name: config.node.defaultBucket })
        if (!bucket) {
            bucket = await buckets.create(config.node.defaultBucket, {
                versioning: config.node.defaultVersioning,
                objectLockEnabled: config.node.objectLockDefault,
                createdBy: 'bootstrap',
                allowReserved: true,
            })
        }

        // a disabled by default tiering policy + lifecycle rule so operators
        // have a starting point in the console
        const tieringPolicies = await repo.count('tiering_policy', { bucketId: bucket.id })
        if (!tieringPolicies) {
            await tiering.createPolicy(bucket, {
                name: 'intelligent-tiering-default',
                enabled: false,
                hotToCoolDays: 30,
                coolToArchiveDays: 180,
                minAccessCount: 2,
                intervalMinutes: 60,
            })
        }
        const lifecycleRules = await repo.count('lifecycle_rule', { bucketId: bucket.id })
        if (!lifecycleRules) {
            await lifecycle.createRule(bucket, {
                name: 'default-retention',
                status: 'Disabled',
                prefix: null,
                transitions: [
                    { days: 30, storageClass: 'STANDARD_IA' },
                    { days: 180, storageClass: 'GLACIER' },
                ],
                expirationDays: null,
                noncurrentVersionExpirationDays: 365,
                noncurrentVersionsToRetain: 10,
                abortIncompleteMultipartDays: 7,
            })
        }

        await repo.insert('setting', {
            key: 'system.info',
            value: { version: VERSION, node: config.node.name, region: config.node.region, bootstrappedAt: util.iso(new Date()) },
            category: 'system',
            updatedBy: 'bootstrap',
        }).catch(() => {})

        return { bucket }
    }

    const bootstrap = async () => {
        if (bootstrapped) return { alreadyBootstrapped: true }
        await ensureSchema(db, { autoMigrate: config.database.autoMigrate })
        await store.init()
        const seeded = await seed()
        replication.init()
        bootstrapped = true

        // metric gauges
        metrics.gauge('objects_total', () => repo.count('directory', { type: 'file', deletedAt: null }))
        metrics.gauge('buckets_total', () => repo.count('bucket'))
        metrics.gauge('versions_total', () => repo.count('object_version'))
        metrics.gauge('bytes_stored_total', async () => Number(await repo.aggregate('directory', 'sum', 'size', { type: 'file', deletedAt: null }) || 0))
        metrics.gauge('replication_backlog', async () => {
            const stats = await replication.stats()

            return Object.entries(stats.byStatus).filter(([s]) => s === 'pending' || s === 'in-flight').reduce((acc, [, v]) => acc + v, 0)
        })
        metrics.gauge('event_delivery_backlog', () => repo.count('event_delivery', { status: 'pending' }))
        metrics.gauge('event_dead_letters', () => repo.count('event_delivery', { status: 'dead' }))
        metrics.gauge('users_total', () => repo.count('user'))
        metrics.gauge('multipart_uploads_open', () => repo.count('multipart_upload', { status: 'in-progress' }))
        metrics.gauge('audit_events_total', () => repo.count('audit_event'))

        return seeded
    }

    const startWorkers = () => {
        if (!config.workers.enabled) return timers
        const push = (timer) => { if (timer) timers.push(timer) }
        push(replication.start(config.workers.replicationIntervalMs))
        push(lifecycle.start(config.workers.lifecycleIntervalMs))
        push(tiering.start(config.workers.tieringIntervalMs))
        if (config.audit.retentionDays) {
            push(setInterval(() => {
                audit.prune().catch((err) => logger.warn?.({ err }, 'audit prune failed'))
            }, config.workers.auditPruneIntervalMs))
        }
        // event delivery/redelivery loop (kept separate from emit() so the data
        // plane never waits on a slow webhook target)
        push(setInterval(() => {
            events.processDue().catch((err) => logger.warn?.({ err }, 'event delivery failed'))
        }, config.workers.eventsIntervalMs))
        push(setInterval(() => {
            objects.abortStaleUploads().catch(() => {})
        }, 6 * 3600000))
        timers.forEach((t) => t.unref?.())

        return timers
    }

    const stopWorkers = () => {
        timers.forEach((t) => clearInterval(t))
        timers.length = 0
    }

    const health = async () => {
        const started = Date.now()
        let dbOk = true
        let dbError = null
        try {
            await repo.get('select 1 as ok')
        } catch (err) {
            dbOk = false
            dbError = err.message
        }
        const storageHealth = await store.health().catch((err) => ({ ok: false, error: err.message }))

        return {
            status: dbOk ? 'ok' : 'degraded',
            version: VERSION,
            node: config.node.name,
            region: config.node.region,
            uptimeSeconds: Math.round(process.uptime()),
            database: {
                driver: config.database.driver, ok: dbOk, error: dbError, latencyMs: Date.now() - started,
            },
            storage: storageHealth,
            encryption: crypto.enabled ? { enabled: true, algorithm: crypto.algorithm, keyId: crypto.keyId } : { enabled: false },
            workers: { enabled: config.workers.enabled, running: timers.length },
            aiTagger: ai_enabled(config),
            servers: {
                webdav: config.servers.webdav.enabled,
                s3: config.servers.s3.enabled,
                rest: true,
                console: config.servers.console.enabled,
            },
        }
    }

    const close = async () => {
        stopWorkers()
        await db.close().catch(() => {})
    }

    return {
        VERSION,
        config,
        logger,
        db,
        repo,
        store,
        crypto,
        audit,
        events,
        metrics,
        iam,
        buckets,
        objects,
        tagger,
        lifecycle,
        tiering,
        replication,
        shares,
        seed,
        bootstrap,
        startWorkers,
        stopWorkers,
        health,
        close,
        isBootstrapped: () => bootstrapped,
        schemaSql,
        migrationsDir,
    }
}

const ai_enabled = (config) => (config.ai.url ? { enabled: true, url: config.ai.url, minConfidence: config.ai.minConfidence } : { enabled: false, engine: 'heuristic' })

module.exports = { createContext, VERSION }
