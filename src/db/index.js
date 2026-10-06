/**
 * Database factory + bootstrap.
 *
 * Two dialects are supported out of the box:
 *   postgres -> production deployments (managed HA, multi-AZ, PITR)
 *   sqlite   -> single node / edge / development (node:sqlite, zero deps)
 *
 * Both expose the same tiny query surface used by `src/core/repository.js`.
 */
const fs = require('fs')
const path = require('path')
const { createPgDb } = require('./pg')
const { createSqliteDb } = require('./sqlite')
const { schemaDDL } = require('./ddl')

const ROOT = path.join(__dirname, '..', '..')

/**
 * Create a database handle.
 * @param {object} opts
 * @param {'postgres'|'sqlite'} [opts.driver]
 * @param {string} [opts.databaseUrl]
 * @param {string} [opts.sqliteFile]
 * @param {boolean} [opts.autoMigrate]
 */
const createDb = (opts = {}) => {
    const driver = opts.driver || (opts.databaseUrl ? 'postgres' : 'sqlite')
    if (driver === 'postgres' || driver === 'pg') {
        if (!opts.databaseUrl) throw new Error('DATABASE_URL is required for the postgres driver')
        const db = createPgDb({ connection: opts.databaseUrl, pool: opts.pool })
        db.knexRef = db.knex

        return db
    }
    if (driver === 'sqlite') {
        return createSqliteDb({ file: opts.sqliteFile })
    }
    throw new Error(`Unsupported DB_DRIVER "${driver}" (expected postgres or sqlite)`)
}

/**
 * Run the knex migrations for a Postgres deployment.
 *
 * `gen_random_uuid()` needs pgcrypto on Postgres < 13, but creating an
 * extension requires elevated rights, so on managed clusters (RDS, Cloud SQL,
 * Neon, Supabase) the statement can legitimately fail - it must not stop the
 * deployment. The application always generates its own UUIDs, the extension is
 * only a database-side default.
 */
const migratePostgres = async (db, opts = {}) => {
    const knex = db.knex
    if (!knex) throw new Error('migratePostgres requires a postgres driver')
    let extension = 'created'
    try {
        await knex.raw('create extension if not exists pgcrypto')
    } catch (err) {
        extension = `unavailable (${err.message.split('\n')[0]})`
        opts.logger?.warn?.({ err }, 'could not create the pgcrypto extension; continuing')
    }
    const [batch, files] = await knex.migrate.latest({
        directory: path.join(ROOT, 'migrations'),
        tableName: 'knex_migrations',
    })

    return { batch, files, extension }
}

/** Create every table for an embedded SQLite deployment (idempotent). */
const bootstrapSqlite = async (db) => {
    await db.exec('pragma foreign_keys = OFF')
    const statements = schemaDDL('sqlite')
    for (const stmt of statements) await db.exec(stmt) // eslint-disable-line no-await-in-loop
    await db.exec('pragma foreign_keys = ON')

    return { statements: statements.length }
}

/**
 * Ensure the schema exists and required seed data is present.
 * Safe to call on every boot.
 */
const ensureSchema = async (db, opts = {}) => {
    let migrated = null
    if (db.dialect === 'sqlite') {
        migrated = await bootstrapSqlite(db)
    } else if (opts.autoMigrate !== false) {
        migrated = await migratePostgres(db, opts)
    }

    return migrated
}

/** Export schema DDL (used by tests, the CLI and the docs generator). */
const schemaSql = (dialect) => schemaDDL(dialect).join(';\n')

/** Location of the migration directory (used by the CLI). */
const migrationsDir = () => path.join(ROOT, 'migrations')

const exists = (file) => fs.existsSync(file)

module.exports = {
    createDb, ensureSchema, migratePostgres, bootstrapSqlite, schemaSql, migrationsDir, exists,
}
