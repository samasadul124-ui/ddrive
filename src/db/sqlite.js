/**
 * SQLite driver (single node / edge / development).
 *
 * Backed by `node:sqlite` which ships with Node.js >= 22.5 (no native build
 * step). Write transactions are serialized through a small mutex so concurrent
 * HTTP requests never interleave BEGIN/COMMIT on the single write connection.
 */
const fs = require('fs')
const path = require('path')
const { AsyncLocalStorage } = require('async_hooks')

const MIN_NODE = [22, 5, 0]

const assertNodeVersion = () => {
    const [major, minor] = process.versions.node.split('.').map(Number)
    if (major > MIN_NODE[0]) return
    if (major === MIN_NODE[0] && minor >= MIN_NODE[1]) return
    const err = new Error(
        `The sqlite storage driver requires Node.js >= ${MIN_NODE.join('.')} (found ${process.versions.node}). `
        + 'Use the postgres driver (DATABASE_URL) or upgrade Node.js.',
    )
    err.statusCode = 500
    throw err
}

const normalizeParam = (value) => {
    if (value === undefined || value === null) return null
    if (typeof value === 'boolean') return value ? 1 : 0
    if (value instanceof Date) return value.toISOString()
    if (typeof value === 'object' && !Buffer.isBuffer(value)) return JSON.stringify(value)

    return value
}

const createSqliteDb = (config = {}) => {
    assertNodeVersion()

    // eslint-disable-next-line global-require
    const { DatabaseSync } = require('node:sqlite')
    const file = config.file || ':memory:'
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true })

    const sqlite = new DatabaseSync(file)
    sqlite.exec('pragma journal_mode = WAL')
    sqlite.exec('pragma foreign_keys = ON')
    sqlite.exec('pragma busy_timeout = 10000')
    sqlite.exec('pragma synchronous = NORMAL')

    const statement = (sql) => {
        try {
            return sqlite.prepare(sql)
        } catch (err) {
            err.message = `${err.message} [sql: ${sql}]`
            throw err
        }
    }

    // Single write queue: serializes transactions and standalone writes so a
    // plain INSERT can never land inside another request's open transaction.
    // Statements issued *inside* a transaction (tracked with AsyncLocalStorage)
    // run immediately - they are already ordered by the caller's control flow.
    const txContext = new AsyncLocalStorage()
    let queue = Promise.resolve()
    let txDepth = 0
    const enqueue = (task) => {
        const run = queue.then(task, task)
        queue = run.then(() => undefined, () => undefined)

        return run
    }
    const serialize = (task) => (txDepth > 0 && !txContext.getStore() ? enqueue(task) : task())

    const doRun = async (sql, params = []) => {
        const res = statement(sql).run(...params.map(normalizeParam))

        return { changes: Number(res.changes || 0), lastInsertRowid: Number(res.lastInsertRowid || 0) }
    }

    const db = {
        dialect: 'sqlite',
        sqlite,
        async all(sql, params = []) {
            return statement(sql).all(...params.map(normalizeParam)).map((r) => ({ ...r }))
        },
        async get(sql, params = []) {
            const row = statement(sql).get(...params.map(normalizeParam))

            return row ? { ...row } : null
        },
        run(sql, params = []) {
            return serialize(() => doRun(sql, params))
        },
        exec(sql) {
            return serialize(() => sqlite.exec(sql))
        },
        transaction(fn) {
            return enqueue(async () => {
                const depth = txDepth
                const name = `sp_${depth}`
                if (depth === 0) await doRun('begin immediate')
                else await doRun(`savepoint ${name}`)
                txDepth = depth + 1
                try {
                    const tx = { ...db, transaction: db.transaction }
                    const result = await txContext.run({ transaction: true }, () => fn(tx))
                    if (depth === 0) await doRun('commit')
                    else await doRun(`release savepoint ${name}`)
                    txDepth = depth

                    return result
                } catch (err) {
                    if (depth === 0) await doRun('rollback')
                    else await doRun(`rollback to savepoint ${name}`)
                    txDepth = depth
                    throw err
                }
            })
        },
        async close() {
            await enqueue(async () => sqlite.close())
        },
    }

    return db
}

module.exports = { createSqliteDb }
