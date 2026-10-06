/**
 * Postgres deployment checks that run without a Postgres server.
 *
 * The pg driver itself is knex + `pg` (no SQL of its own), so what can actually
 * rot - and did - is the migration path. These tests drive the real migration
 * files with a recording knex stub and assert the resulting schema matches what
 * the runtime code queries, so a `DB_DRIVER=postgres` deployment cannot boot
 * into a half-created database.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const { tables } = require('../src/db/schema')
const { schemaDDL } = require('../src/db/ddl')

const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations')
const migrationFiles = () => fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.js')).sort()

/**
 * A knex double that records DDL instead of talking to a server.
 * `existing` is the set of tables already present.
 */
/** A builder double: every method chains, nothing is sent anywhere. */
const chainable = () => {
    const target = function builder() {}
    const handler = {
        get: (t, prop) => {
            if (prop === 'then') return undefined
            if (prop === Symbol.toPrimitive || typeof prop === 'symbol') return undefined

            return () => proxy
        },
        apply: () => proxy,
    }
    const proxy = new Proxy(target, handler)

    return proxy
}

const fakeKnex = (existing = new Set()) => {
    const state = {
        created: new Set(), renamed: [], raw: [], dropped: [], columnsChecked: [], builderTables: [], archived: [],
    }

    // knex('directory') / knex(tableBuilder) -> chainable query builder
    const knex = (arg) => {
        if (typeof arg === 'string') state.builderTables.push(arg)

        return chainable()
    }
    knex.raw = async (sql) => {
        state.raw.push(sql)
        // the baseline migration runs portable DDL through raw()
        const created = /create table if not exists "([^"]+)"\s*\(([\s\S]*)\)\s*$/.exec(sql)
        if (created) {
            state.created.add(created[1])
            // model the resulting column set so later runs can tell v2 from legacy
            const cols = new Set()
            created[2].split('\n').forEach((line) => {
                if (/^\s*constraint/i.test(line)) return
                const col = /^\s*"([^"]+)"/.exec(line)
                if (col) cols.add(col[1])
            })
            state.tableColumns.set(created[1], cols)
        }
        const plain = /^create table if not exists "([^"]+)"\s*\(([^)]*)\)/.exec(sql)
        if (plain && !created) {
            state.created.add(plain[1])
            const cols = new Set()
            plain[2].split(',').forEach((c) => {
                const col = /^\s*"([^"]+)"/.exec(c)
                if (col) cols.add(col[1])
            })
            state.tableColumns.set(plain[1], cols)
        }
        const archived = /^insert into "(legacy_[a-z]+)" \([^)]*\) select [^)]* from "([a-z_]+)"/.exec(sql.trim())
        if (archived) state.archived.push({ archive: archived[1], from: archived[2] })
        const dropped = /^drop table "([a-z_]+)"/.exec(sql.trim())
        if (dropped) {
            state.dropped.push(dropped[1])
            state.created.delete(dropped[1])
            state.tableColumns.delete(dropped[1])
            existing.delete(dropped[1])
        }
    }
    knex.fn = { now: () => 'now()' }
    state.tableColumns = new Map()
    knex.schema = {
        hasTable: async (name) => existing.has(name) || state.created.has(name),
        hasColumn: async (name, column) => {
            state.columnsChecked.push([name, column])

            // read through state so a caller-supplied column map is honoured
            return (state.tableColumns.get(name) || new Set()).has(column)
        },
        createTable: async (name, cb) => {
            state.created.add(name)
            if (typeof cb === 'function') cb(chainable())
        },
        renameTable: async (from, to) => {
            state.renamed.push([from, to])
            existing.delete(from)
            state.created.add(to)
        },
        dropTableIfExists: async (name) => {
            state.dropped.push(name)
            state.created.delete(name)
        },
    }
    state.knex = knex

    return { knex, state, existing }
}

/** Run every migration in filename order against an existing knex double. */
const applyMigrations = async (state, knex) => {
    for (const file of migrationFiles()) {
        // eslint-disable-next-line global-require, import/no-dynamic-require
        const migration = require(path.join(MIGRATIONS_DIR, file))
        // eslint-disable-next-line no-await-in-loop
        await migration.up(knex)
    }

    return state
}

/** Fresh database -> run every migration sequentially. */
const runMigrations = async (existing = new Set(), columns = new Map()) => {
    const { knex, state } = fakeKnex(existing)
    if (columns && columns.size) state.tableColumns = columns

    return applyMigrations(state, knex)
}

/** Tables the v2 schema says must exist. */
const schemaTables = Object.keys(tables)

/** Tables/columns the runtime queries, scraped from the source tree. */
const runtimeTableUsage = () => {
    const root = path.join(__dirname, '..', 'src')
    const found = new Map()
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name)
            if (entry.isDirectory()) walk(full)
            else if (entry.name.endsWith('.js')) {
                const src = fs.readFileSync(full, 'utf8')
                const re = /repo\.(?:find|findOne|insert|insertMany|update|delete|count|exists|aggregate|sum|upsert)\s*\(\s*'([a-z_]+)'/g
                let m
                // eslint-disable-next-line no-cond-assign
                while ((m = re.exec(src))) {
                    if (!found.has(m[1])) found.set(m[1], new Set())
                    found.get(m[1]).add(path.relative(root, full))
                }
            }
        }
    }
    walk(root)

    return found
}

test('the postgres migrations create every table the runtime uses', async () => {
    const state = await runMigrations()
    const created = new Set(state.created)

    for (const table of schemaTables) {
        assert.ok(created.has(table), `migration never creates table "${table}"`)
    }

    const usage = runtimeTableUsage()
    assert.ok(usage.size >= 20, `expected the runtime to query many tables, found ${usage.size}`)
    for (const [table, files] of usage) {
        assert.ok(schemaTables.includes(table), `"${table}" is queried by ${[...files].join(', ')} but is not in the schema definition`)
        assert.ok(created.has(table), `"${table}" is queried by ${[...files].join(', ')} but no migration creates it`)
    }
})

test('the baseline migration is dialect complete and idempotent', async () => {
    const pg = schemaDDL('pg')
    const sqlite = schemaDDL('sqlite')

    assert.equal(pg.length, sqlite.length, 'pg and sqlite must describe the same objects')
    for (const statement of pg) {
        assert.match(statement, /^(create table if not exists|create index if not exists)/)
        assert.doesNotMatch(statement, /autoincrement|pragma/i, 'sqlite-ism leaked into the postgres DDL')
    }
    // uuid defaults are generated in-database on pg, never by the app
    assert.match(pg.join('\n'), /gen_random_uuid\(\)/)

    // running it twice on the same database leaves the same tables behind
    const once = await runMigrations()
    const before = [...once.created].sort()
    await applyMigrations(once, once.knex)
    assert.deepEqual([...once.created].sort(), before)
    assert.equal(once.archived.length, 0, 'a v2 database must never be re-archived')
})

test('a pre-2.0 database is upgraded without data loss', async () => {
    // the legacy 1.0 migration created these two tables with an incompatible shape
    const columns = new Map([
        ['directory', new Set(['id', 'name', 'parentId', 'type', 'createdAt'])],
        ['block', new Set(['id', 'fileId', 'url', 'size', 'iv', 'createdAt'])],
    ])
    const state = await runMigrations(new Set(['directory', 'block']), columns)

    // the legacy rows are archived, never dropped without a copy
    assert.deepEqual(state.archived, [
        { archive: 'legacy_block', from: 'block' },
        { archive: 'legacy_directory', from: 'directory' },
    ])
    assert.deepEqual(state.dropped, ['block', 'directory'], 'legacy tables must be archived in FK-safe order')
    assert.ok(state.columnsChecked.some(([t, c]) => t === 'directory' && c === 'path'))

    // ...and the v2 tables are then created
    for (const table of schemaTables) {
        assert.ok(state.created.has(table), `"${table}" missing after upgrading a legacy database`)
    }

    // a database that already has v2-shaped tables is left alone
    const v2 = new Map([
        ['directory', new Set(['id', 'bucketId', 'path'])],
        ['block', new Set(['id', 'versionId'])],
    ])
    const clean = await runMigrations(new Set(['directory', 'block']), v2)
    assert.deepEqual(clean.archived, [], 'v2 tables must not be archived or replaced')
    assert.deepEqual(clean.dropped, [])
    assert.deepEqual(clean.renamed, [])
})

test('the migration set is discoverable by knex in filename order', () => {
    const files = migrationFiles()
    assert.ok(files.length >= 2, `expected the legacy + baseline migrations, got ${JSON.stringify(files)}`)
    const sorted = [...files].sort()
    assert.deepEqual(files, sorted)
    for (const file of files) {
        // eslint-disable-next-line global-require, import/no-dynamic-require
        const mod = require(path.join(MIGRATIONS_DIR, file))
        assert.equal(typeof mod.up, 'function', `${file} must export up()`)
        assert.equal(typeof mod.down, 'function', `${file} must export down()`)
    }
    // the baseline runs after the legacy migration
    assert.ok(files[files.length - 1].startsWith('2026'), `the baseline must be the newest migration, got ${files[files.length - 1]}`)
})
