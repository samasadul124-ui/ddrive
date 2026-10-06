/**
 * Configuration: everything is an environment variable with a safe default, so
 * a fresh checkout boots with `node bin/ddrive` and nothing else.
 *
 * Values are validated (and normalized into absolute paths / booleans) once at
 * startup; the rest of the codebase reads the returned object.
 */
const path = require('path')
const fs = require('fs')
const os = require('os')

const bool = (value, fallback) => {
    if (value === undefined || value === null || value === '') return fallback
    if (typeof value === 'boolean') return value

    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase())
}

const int = (value, fallback) => {
    const parsed = Number.parseInt(value, 10)

    return Number.isFinite(parsed) ? parsed : fallback
}

const list = (value) => (value === undefined || value === null ? [] : String(value).split(',').map((v) => v.trim()).filter(Boolean))

const absolute = (value, cwd) => (path.isAbsolute(value) ? value : path.resolve(cwd, value))

const readSecretFile = (file) => {
    if (!file) return ''
    try {
        return fs.readFileSync(file, 'utf8').trim()
    } catch {
        return ''
    }
}

const readWebhooks = (env, cwd) => {
    if (env.WEBHOOKS) return list(env.WEBHOOKS)
    const fromEnvFile = env.WEBHOOK_FILE ? readSecretFile(absolute(env.WEBHOOK_FILE, cwd)) : ''
    const fromDefault = readSecretFile(path.join(cwd, 'webhook.txt'))

    return list(fromEnvFile || fromDefault)
}

const loadConfig = (env = process.env, opts = {}) => {
    const cwd = opts.cwd || process.cwd()
    const nodeEnv = env.NODE_ENV || 'development'
    const dataDir = absolute(env.DATA_DIR || './data', cwd)

    const database = {
        driver: (env.DB_DRIVER || (env.DATABASE_URL ? 'postgres' : 'sqlite')).toLowerCase(),
        url: env.DATABASE_URL || '',
        sqliteFile: absolute(env.SQLITE_FILE || path.join(dataDir, 'ddrive.sqlite'), cwd),
        autoMigrate: bool(env.AUTO_MIGRATE, true),
        pool: { min: int(env.DB_POOL_MIN, 0), max: int(env.DB_POOL_MAX, 10) },
        // sqlite tuning
        busyTimeout: int(env.SQLITE_BUSY_TIMEOUT, 5000),
    }

    const tier = (name) => {
        const driver = (env[`${name}_DRIVER`] || '').toLowerCase() || null
        if (!driver) return null

        return {
            driver,
            directory: env[`${name}_DIRECTORY`] ? absolute(env[`${name}_DIRECTORY`], cwd) : path.join(dataDir, name.toLowerCase()),
            endpoint: env[`${name}_ENDPOINT`] || '',
            bucket: env[`${name}_BUCKET`] || '',
            region: env[`${name}_REGION`] || 'us-east-1',
            prefix: env[`${name}_PREFIX`] || '',
            accessKeyId: env[`${name}_ACCESS_KEY_ID`] || '',
            secretAccessKey: env[`${name}_SECRET_ACCESS_KEY`] || env[`${name}_SECRET`] || '',
            forcePathStyle: bool(env[`${name}_FORCE_PATH_STYLE`], true),
        }
    }

    const storage = {
        driver: (env.STORAGE_DRIVER || 'local').toLowerCase(),
        dataDir,
        directory: absolute(env.STORAGE_DIRECTORY || path.join(dataDir, 'chunks'), cwd),
        chunkSize: Math.min(int(env.CHUNK_SIZE, 25165824), 26109542),
        concurrency: int(env.UPLOAD_CONCURRENCY, 3),
        webhooks: readWebhooks(env, cwd),
        // override the Discord REST base (self-hosted webhook proxies, tests)
        discordApiBase: (env.DISCORD_API_BASE || 'https://discord.com/api').replace(/\/+$/, ''),
        legacySecret: env.SECRET || '',
        // requests with a declared content-length below this are hashed and
        // compared against `x-amz-content-sha256` (0 disables the check)
        verifyLimitBytes: int(env.S3_VERIFY_PAYLOAD_BYTES, 268435456),
        cool: tier('TIER_COOL'),
        archive: tier('TIER_ARCHIVE'),
        // memory driver is testing only
        maxChunkSize: 26109542,
    }

    const publicAccess = (env.PUBLIC_ACCESS || '').toUpperCase() || null
    if (publicAccess && !['READ_ONLY_FILE', 'READ_ONLY_PANEL'].includes(publicAccess)) {
        throw new Error(`Invalid PUBLIC_ACCESS ${publicAccess}: expected READ_ONLY_FILE, READ_ONLY_PANEL or empty`)
    }

    const [authUser, authPass] = String(env.AUTH || '').split(':')
    const masterKey = env.MASTER_KEY || env.ENCRYPTION_KEY || ''
    const kmsEndpoint = env.KMS_ENDPOINT || ''

    const security = {
        masterKey,
        masterKeyFile: readSecretFile(env.MASTER_KEY_FILE),
        algorithm: (env.ENCRYPTION_ALGORITHM || 'aes-256-gcm').toLowerCase(),
        kmsEndpoint,
        kmsToken: env.KMS_TOKEN || '',
        kmsKeyId: env.KMS_KEY_ID || 'ddrive-master',
        kmsProvider: env.KMS_PROVIDER || (kmsEndpoint ? 'http' : null),
        legacySecret: env.SECRET || '',
        publicAccess,
        allowPublicShare: bool(env.ALLOW_PUBLIC_SHARE, true),
        trustProxy: bool(env.TRUST_PROXY, true),
        requireHttps: bool(env.REQUIRE_HTTPS, false),
        corsOrigins: list(env.CORS_ORIGINS),
        sessionSecret: env.SESSION_SECRET || '',
        maxKeys: int(env.MAX_KEYS, 1000),
        presignMaxExpiry: int(env.PRESIGN_MAX_EXPIRY, 604800),
        bootstrap: {
            username: env.BOOTSTRAP_ADMIN_USER || authUser || 'admin',
            password: env.BOOTSTRAP_ADMIN_PASSWORD || authPass || '',
        },
    }

    const audit = {
        file: env.AUDIT_LOG_FILE ? absolute(env.AUDIT_LOG_FILE, cwd) : '',
        webhookUrl: env.AUDIT_WEBHOOK_URL || '',
        syslogHost: env.AUDIT_SYSLOG_HOST || '',
        syslogPort: int(env.AUDIT_SYSLOG_PORT, 514),
        retentionDays: int(env.AUDIT_RETENTION_DAYS, 0),
    }

    const servers = {
        host: env.HOST || '0.0.0.0',
        port: int(env.PORT, 3000),
        requestTimeout: int(env.REQUEST_TIMEOUT, 60000),
        bodyLimit: int(env.BODY_LIMIT, 5 * 1024 * 1024),
        webdav: {
            enabled: bool(env.WEBDAV_ENABLED, true),
            path: env.WEBDAV_PATH || '/webdav',
            maxDepth: int(env.WEBDAV_MAX_DEPTH, 32),
            autoMkcol: bool(env.WEBDAV_AUTO_MKCOL, true),
        },
        s3: {
            enabled: bool(env.S3_ENABLED, true),
            path: env.S3_PATH || '/s3',
            region: env.S3_REGION || env.REGION || 'us-east-1',
            virtualHost: env.S3_VIRTUAL_HOST || '',
        },
        console: { enabled: bool(env.CONSOLE_ENABLED, true) },
        metrics: { enabled: bool(env.METRICS_ENABLED, true) },
        health: { enabled: bool(env.HEALTH_ENABLED, true) },
    }

    const workers = {
        enabled: bool(env.WORKERS_ENABLED, true),
        lifecycleIntervalMs: int(env.LIFECYCLE_INTERVAL_MS, 900000),
        tieringIntervalMs: int(env.TIERING_INTERVAL_MS, 3600000),
        replicationIntervalMs: int(env.REPLICATION_INTERVAL_MS, 3000),
        eventsIntervalMs: int(env.EVENTS_INTERVAL_MS, 2000),
        auditPruneIntervalMs: int(env.AUDIT_PRUNE_INTERVAL_MS, 86400000),
        multipartTtlDays: int(env.MULTIPART_TTL_DAYS, 7),
        replicationMaxAttempts: int(env.REPLICATION_MAX_ATTEMPTS, 8),
    }

    const node = {
        name: env.NODE_NAME || os.hostname(),
        region: env.REGION || 'primary',
        defaultBucket: env.DEFAULT_BUCKET || 'ddrive',
        defaultVersioning: env.DEFAULT_VERSIONING || 'enabled',
        objectLockDefault: bool(env.OBJECT_LOCK_ENABLED, false),
    }

    const ai = {
        url: env.AI_TAGGER_URL || '',
        token: env.AI_TAGGER_TOKEN || '',
        minConfidence: Number(env.AI_MIN_CONFIDENCE || 0.5),
        timeoutMs: int(env.AI_TAGGER_TIMEOUT_MS, 8000),
    }

    const config = {
        nodeEnv,
        isProduction: nodeEnv === 'production',
        logLevel: env.LOG_LEVEL || (nodeEnv === 'production' ? 'info' : 'debug'),
        database,
        storage,
        security,
        audit,
        servers,
        workers,
        node,
        ai,
        dataDir,
    }
    if (opts.validate) validate(config)

    return config
}

/** Fail fast on configuration that would be insecure or broken in production. */
const validate = (config) => {
    const problems = []
    if (config.isProduction) {
        if (config.storage.driver === 'memory') problems.push('STORAGE_DRIVER=memory must not be used in production')
        if (!config.security.masterKey && !config.security.masterKeyFile && !config.security.kmsEndpoint) {
            problems.push('MASTER_KEY (or KMS_ENDPOINT) is required in production: data would be stored unencrypted')
        }
        if (!config.security.bootstrap.password && !process.env.BOOTSTRAP_ADMIN_PASSWORD) {
            problems.push('BOOTSTRAP_ADMIN_PASSWORD is required in production for the initial administrator')
        }
    }
    if (problems.length) throw new Error(`Invalid configuration:\n - ${problems.join('\n - ')}`)

    return true
}

module.exports = {
    loadConfig,
    validate,
    bool,
    int,
    list,
    VALID_PUBLIC_ACCESS: ['READ_ONLY_FILE', 'READ_ONLY_PANEL'],
    DEFAULT_CHUNK_SIZE: 25165824,
    MAX_CHUNK_SIZE: 26109542,
}
