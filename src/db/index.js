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

/** Run the knex migrations for a Postgres deployment. */
const migratePostgres = async (db) => {
    const knex = db.knex
    if (!knex) throw new Error('migratePostgres requires a postgres driver')
    await knex.raw('create extension if not exists pgcrypto')
    const [batch, files] = await knex.migrate.latest({
        directory: path.join(ROOT, 'migrations'),
        tableName: 'knex_migrations',
    })

    return { batch, files }
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
        migrated = await migratePostgres(db)
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
