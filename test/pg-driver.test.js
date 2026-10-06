/**
 * Postgres driver integration.
 *
 * The application is booted end to end on `DB_DRIVER=postgres` against an
 * in-process PostgreSQL engine emulation (pg-mem) - same SQL, same driver
 * interface, no server required - so the production path is exercised by the
 * normal test run instead of only by hand on a live cluster.
 *
 * Covered here because they are Postgres-specific:
 *   - the migration baseline creating the schema the runtime queries
 *   - the 1.0 -> 2.0 upgrade archiving the legacy tables
 *   - jsonb columns: node-postgres sends a JS array as a Postgres *array
 *     literal*, so JSON values must be stringified by the repository
 *   - the audit log's advisory lock and the IAM policy lookups
 *   - objects, versioning, WebDAV and lifecycle over the pg driver
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const { Buffer } = require('node:buffer')

const ADMIN = { username: 'admin', password: 'TestPassw0rd!x' }
const PG_URL = 'postgres://ddrive:ddrive@localhost:5432/ddrive'

let pgmem = null
try {
    // eslint-disable-next-line global-require
    pgmem = require('pg-mem')
} catch {
    pgmem = null
}

/**
 * Point the `pg` module at a fresh in-memory database.
 *
 * knex resolves its driver in the Client constructor (`_driver()` ->
 * `require('pg')`), so replacing the cached module before each `createDb()` call
 * gives every test its own isolated database.
 */
const useMemoryPostgres = () => {
    const mem = pgmem.newDb({ autoCreateForeignKeyIndices: true })
    const id = (args, returns, implementation) => mem.public.registerFunction({
        name: id.name, args, returns, implementation, impure: true,
    })
    void id

    mem.public.registerFunction({
        name: 'gen_random_uuid', args: [], returns: pgmem.DataType.uuid, implementation: () => crypto.randomUUID(), impure: true,
    })
    mem.public.registerFunction({
        name: 'now', args: [], returns: pgmem.DataType.timestamptz, implementation: () => new Date(), impure: true,
    })
    mem.public.registerFunction({
        name: 'version', args: [], returns: pgmem.DataType.text, implementation: () => 'PostgreSQL 15.4 (pg-mem)',
    })
    mem.public.registerFunction({
        name: 'current_database', args: [], returns: pgmem.DataType.text, implementation: () => 'ddrive',
    })
    // used by the audit writer to serialise the hash chain across writers
    mem.public.registerFunction({
        name: 'pg_advisory_xact_lock', args: [pgmem.DataType.integer], returns: pgmem.DataType.integer, implementation: () => 1, impure: true,
    })
    mem.public.registerFunction({
        name: 'pg_advisory_xact_lock', args: [pgmem.DataType.text], returns: pgmem.DataType.integer, implementation: () => 1, impure: true,
    })

    // eslint-disable-next-line global-require
    const realPg = require('pg')
    const adapter = mem.adapters.createPg()
    const pgPath = require.resolve('pg')
    require.cache[pgPath].exports = {
        ...adapter, types: realPg.types, defaults: realPg.defaults, DatabaseError: realPg.DatabaseError,
    }

    return mem
}

const pgEnv = () => ({ DB_DRIVER: 'postgres', DATABASE_URL: PG_URL })

const requirePgMem = (t) => {
    if (!pgmem) {
        t.skip('pg-mem is not installed (optional dev dependency)')

        return false
    }

    return true
}

test('the application boots and serves requests on the postgres driver', async (t) => {
    if (!requirePgMem(t)) return
    useMemoryPostgres()
    // eslint-disable-next-line global-require
    const { createTestServer } = require('./helpers')
    const t2 = await createTestServer(pgEnv())
    try {
        // --- buckets and objects
        const created = await t2.json('POST', '/api/buckets', { name: 'pg-bucket', versioning: 'enabled' })
        assert.equal(created.statusCode, 201, created.body)

        const put = await t2.authed({
            method: 'PUT',
            url: '/api/buckets/pg-bucket/objects/docs/hello.txt',
            headers: { 'content-type': 'text/plain' },
            payload: 'postgres says hi',
        })
        assert.equal(put.statusCode, 201, put.body)

        const got = await t2.authed({ method: 'GET', url: '/api/buckets/pg-bucket/objects/docs/hello.txt/download' })
        assert.equal(got.statusCode, 200)
        assert.equal(got.body, 'postgres says hi')

        // --- the row really is in the schema the migrations created
        const node = await t2.context.objects.getNode((await t2.context.buckets.get('pg-bucket')).id, 'docs/hello.txt')
        assert.equal(node.size, 'postgres says hi'.length)
        assert.ok(node.latestVersionId)

        // --- versioning keeps both revisions, with the checksum chain intact
        const second = await t2.authed({
            method: 'PUT',
            url: '/api/buckets/pg-bucket/objects/docs/hello.txt',
            headers: { 'content-type': 'text/plain' },
            payload: 'second revision',
        })
        assert.equal(second.statusCode, 201)
        const versions = await t2.json('GET', '/api/buckets/pg-bucket/objects/docs/hello.txt/versions')
        assert.equal(versions.statusCode, 200, versions.body)
        assert.equal(t2.body(versions).versions.length, 2)

        // --- listing, tagging (jsonb) and lifecycle (timestamps + json)
        const listing = await t2.json('GET', '/api/buckets/pg-bucket/objects?prefix=docs/')
        assert.equal(listing.statusCode, 200)
        assert.deepEqual(t2.body(listing).objects.map((o) => o.key), ['docs/hello.txt'])

        const tagged = await t2.json('PUT', '/api/buckets/pg-bucket/objects/docs/hello.txt/tags', { tags: { env: 'prod', team: 'storage' } })
        assert.equal(tagged.statusCode, 200, tagged.body)
        const tags = await t2.json('GET', '/api/buckets/pg-bucket/objects/docs/hello.txt/tags')
        assert.equal(tags.statusCode, 200)
        assert.deepEqual(t2.body(tags).tags, { env: 'prod', team: 'storage' })

        const lifecycle = await t2.json('POST', '/api/buckets/pg-bucket/lifecycle', {
            name: 'expire-tmp', prefix: 'tmp/', expireAfterDays: 7, status: 'enabled',
        })
        assert.equal(lifecycle.statusCode, 201, lifecycle.body)
        const rules = await t2.json('GET', '/api/buckets/pg-bucket/lifecycle')
        assert.equal(rules.statusCode, 200)
        assert.ok(t2.body(rules).rules.some((r) => r.name === 'expire-tmp'))

        // --- WebDAV on the same database
        const propfind = await t2.authed({ method: 'PROPFIND', url: '/webdav/pg-bucket/docs/', headers: { depth: '1' } })
        assert.equal(propfind.statusCode, 207, propfind.body)
        assert.match(propfind.body, /hello\.txt/)

        // --- the audit log is chained (it takes a pg advisory lock to do so)
        const audit = await t2.json('GET', '/api/admin/audit?limit=50')
        assert.equal(audit.statusCode, 200, audit.body)
        const events = t2.body(audit).events
        assert.ok(events.length >= 4, `expected audit events, got ${events.length}`)
        assert.ok(events.some((e) => e.action === 'object.put'))
        const verification = await t2.context.audit.verify()
        assert.equal(verification.ok, true, JSON.stringify(verification))
    } finally {
        await t2.close()
    }
})

test('jsonb values round-trip as arrays and objects over the postgres driver', async (t) => {
    if (!requirePgMem(t)) return
    useMemoryPostgres()
    // eslint-disable-next-line global-require
    const { createTestServer } = require('./helpers')
    const t2 = await createTestServer(pgEnv())
    try {
        const { repo } = t2.context
        const row = await repo.insert('setting', { key: 'json-probe', value: { list: [1, 2, { deep: true }], text: 'x', n: null } })
        assert.equal(row.key, 'json-probe')
        const read = await repo.findOne('setting', { key: 'json-probe' })
        assert.deepEqual(read.value, { list: [1, 2, { deep: true }], text: 'x', n: null })

        // a role's `policies` list is an array of objects - the shape that broke
        // when node-postgres turned the JS array into a Postgres array literal
        const roles = await repo.find('role', {})
        const admins = roles.find((r) => r.name === 'Administrators')
        assert.ok(Array.isArray(admins.policies), `role policies must be an array, got ${JSON.stringify(admins.policies)}`)
        assert.deepEqual(admins.policies, [{ name: 'AdministratorAccess' }])

        // ...and the array survives an update (jsonb is not append-only)
        await repo.update('role', { name: 'Administrators' }, { policies: [{ name: 'AdministratorAccess' }, { name: 'AuditorAccess' }] })
        const updated = await repo.findOne('role', { name: 'Administrators' })
        assert.equal(updated.policies.length, 2)

        // policy documents are objects with nested statements
        const policy = await repo.findOne('policy', { name: 'AdministratorAccess' })
        assert.ok(policy.document && Array.isArray(policy.document.Statement), JSON.stringify(policy.document))
    } finally {
        await t2.close()
    }
})

test('a pre-2.0 postgres database is upgraded in place', async (t) => {
    if (!requirePgMem(t)) return
    const mem = useMemoryPostgres()

    // Recreate the 1.0 schema (migration ..._1.0.0.js) with its columns and
    // rows. The 1.0 tables also declared a primary key and two indexes, but
    // pg-mem reserves the implicit `<table>_pkey` name forever after a DROP
    // TABLE (PostgreSQL releases it with the table), which would collide with
    // the v2 `directory_pkey`. Those declarations are therefore left out: the
    // behaviour under test here is the archiving of the *rows*.
    mem.public.none('create table "directory" ("id" uuid not null default gen_random_uuid(), '
        + '"name" text not null, "parentId" uuid, "type" text not null, "createdAt" timestamp not null default now())')
    mem.public.none('create table "block" ("id" uuid not null default gen_random_uuid(), '
        + '"fileId" uuid not null, "url" text not null, "size" integer not null, "iv" text, "createdAt" timestamp not null default now())')
    mem.public.none("insert into \"directory\" (\"name\", \"type\") values ('root', 'directory')")
    mem.public.none("insert into \"block\" (\"fileId\", \"url\", \"size\") values (gen_random_uuid(), 'https://cdn.example/1', 4096)")

    // eslint-disable-next-line global-require
    const { createTestServer } = require('./helpers')
    const t2 = await createTestServer(pgEnv())
    try {
        // the legacy tables were archived, rows and all (raw SQL: the repository
        // only exposes tables declared in the schema)
        const archivedDir = await t2.context.repo.db.all('select * from legacy_directory')
        const archivedBlock = await t2.context.repo.db.all('select * from legacy_block')
        assert.equal(archivedDir.length, 1, 'the legacy directory row must be preserved')
        assert.equal(archivedDir[0].name, 'root')
        assert.equal(archivedBlock.length, 1)
        assert.equal(archivedBlock[0].url, 'https://cdn.example/1')

        // `directory` is now the v2 table (it has a path column), and it is empty
        const node = await t2.context.objects.getNode((await t2.context.buckets.create('upgraded', {})).id, 'nothing.txt')
        assert.equal(node, null)
        const deadBlocks = await t2.context.repo.find('block', {})
        assert.equal(deadBlocks.length, 0, 'the v2 block table must not inherit legacy rows')

        // and the upgraded database serves objects normally
        const bucket = await t2.json('POST', '/api/buckets', { name: 'upgraded', versioning: 'enabled' })
        assert.ok([201, 409].includes(bucket.statusCode), bucket.body)
        const put = await t2.authed({
            method: 'PUT',
            url: '/api/buckets/upgraded/objects/after-upgrade.txt',
            headers: { 'content-type': 'text/plain' },
            payload: 'written on a migrated database',
        })
        assert.equal(put.statusCode, 201, put.body)
        const got = await t2.authed({ method: 'GET', url: '/api/buckets/upgraded/objects/after-upgrade.txt/download' })
        assert.equal(got.body, 'written on a migrated database')
    } finally {
        await t2.close()
    }
})

test('a fresh postgres install gets exactly the v2 schema, with no legacy tables', async (t) => {
    if (!requirePgMem(t)) return
    const mem = useMemoryPostgres()
    // eslint-disable-next-line global-require
    const { createTestServer } = require('./helpers')
    const t2 = await createTestServer(pgEnv())
    try {
        const { tables } = require('../src/db/schema')
        const rows = await t2.context.repo.db.all("select table_name from information_schema.tables where table_schema = 'public'")
        const present = new Set(rows.map((r) => r.table_name))
        for (const table of Object.keys(tables)) {
            assert.ok(present.has(table), `missing table ${table}`)
        }
        for (const legacy of ['legacy_directory', 'legacy_block']) {
            assert.equal(present.has(legacy), false, `${legacy} must not exist on a fresh install`)
        }
        const policy = await t2.context.repo.findOne('policy', { name: 'AdministratorAccess' })
        assert.ok(policy, 'builtin policies must be seeded')
        assert.ok(policy.document, 'the policy document must round-trip as an object')
    } finally {
        await t2.close()
    }
    void mem
})
