/**
 * DDrive 2.0 baseline schema (Postgres / production).
 *
 * This application was rewritten from a small flat virtual filesystem
 * (`directory` + `block`, see 20230104113348_1.0.0.js) into a multi-tenant
 * object store. The legacy migration no longer describes the schema the runtime
 * needs, and on its own it left a Postgres deployment with 2 of the 26 required
 * tables - every query failed at runtime.
 *
 * This migration creates the complete v2 schema from the single declarative
 * definition in `src/db/schema.js`. SQLite deployments bootstrap from that same
 * definition, so the two dialects can no longer drift apart.
 *
 * Pre-2.0 tables that share a name with a v2 table but an incompatible shape are
 * copied into `legacy_<name>` (rows preserved, never dropped) and then removed.
 * Removal - rather than a rename - is deliberate: PostgreSQL keeps the old index
 * and constraint names when a table is renamed, so a renamed `directory` would
 * make the new `directory` table fail with `relation "directory_pkey" already
 * exists`. Dropping frees those names.
 *
 * The archive is written with an explicit copy instead of
 * `create table legacy_x as select * from x` so that the upgrade path is
 * exercised by the test suite (test/pg-driver.test.js) against a real
 * PostgreSQL engine emulation. The shapes below mirror the frozen 1.0 schema in
 * 20230104113348_1.0.0.js; v2 never reads them.
 */
const { schemaDDL } = require('../src/db/ddl')

/**
 * Legacy tables to archive, in FK-safe order (block references directory).
 * `sentinel` is a column that only the v2 shape has, so a database that already
 * has v2 tables is never touched.
 */
const LEGACY_TABLES = [
    {
        table: 'block',
        sentinel: 'versionId',
        columns: ['id', 'fileId', 'url', 'size', 'iv', 'createdAt'],
        ddl: 'create table if not exists "legacy_block" ('
            + '"id" uuid not null, "fileId" uuid, "url" text, "size" integer, "iv" text, "createdAt" timestamp)',
    },
    {
        table: 'directory',
        sentinel: 'path',
        columns: ['id', 'name', 'parentId', 'type', 'createdAt'],
        ddl: 'create table if not exists "legacy_directory" ('
            + '"id" uuid not null, "name" text, "parentId" uuid, "type" text, "createdAt" timestamp)',
    },
]

exports.up = async (knex) => {
    for (const {
        table, sentinel, columns, ddl,
    } of LEGACY_TABLES) {
        // eslint-disable-next-line no-await-in-loop
        if (!(await knex.schema.hasTable(table))) continue
        // eslint-disable-next-line no-await-in-loop
        if (await knex.schema.hasColumn(table, sentinel)) continue // already v2
        // eslint-disable-next-line no-await-in-loop
        await knex.raw(ddl)
        // keep the rows (and only the rows: an archive does not need the
        // legacy constraints, which could reject a legacy dataset outright)
        const list = columns.map((c) => `"${c}"`).join(', ')
        // eslint-disable-next-line no-await-in-loop
        await knex.raw(`insert into "legacy_${table}" (${list}) select ${list} from "${table}"`)
        // eslint-disable-next-line no-await-in-loop
        await knex.raw(`drop table "${table}"`)
    }

    // create every v2 table + index (statements are `if not exists`, so this is
    // safe on a fresh, an archived and a partially migrated database alike)
    for (const statement of schemaDDL('pg')) {
        // eslint-disable-next-line no-await-in-loop
        await knex.raw(statement)
    }
}

exports.down = async (knex) => {
    const names = schemaDDL('pg')
        .map((sql) => /create table if not exists "([^"]+)"/.exec(sql)?.[1])
        .filter(Boolean)
        .reverse()
    for (const name of names) {
        // eslint-disable-next-line no-await-in-loop
        await knex.schema.dropTableIfExists(name)
    }
    // restore the archived pre-2.0 tables (rows only) in FK-safe order
    for (const { table, columns } of [...LEGACY_TABLES].reverse()) {
        // eslint-disable-next-line no-await-in-loop
        if (!(await knex.schema.hasTable(`legacy_${table}`))) continue
        // eslint-disable-next-line no-await-in-loop
        if (await knex.schema.hasTable(table)) continue
        // eslint-disable-next-line no-await-in-loop
        await knex.raw(`create table "${table}" as select * from "legacy_${table}"`)
        void columns
    }
}
