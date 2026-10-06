/**
 * Repository: a small, dialect-neutral data access layer.
 *
 * Services never hand-write SQL for basic CRUD; they describe rows in terms of
 * the schema (src/db/schema.js) and the repository takes care of
 *   - safe parameter binding (`?` placeholders in every dialect)
 *   - row hydration/codecs (json, boolean, timestamp, bigint)
 *   - transactions (including nested savepoints on sqlite)
 */
const { randomUUID } = require('crypto')
const { tables } = require('../db/schema')

const OPERATORS = { gt: '>', gte: '>=', lt: '<', lte: '<=', ne: '<>' }

const hydration = {}
Object.entries(tables).forEach(([name, table]) => {
    const map = {}
    Object.entries(table.columns).forEach(([col, def]) => { map[col] = def.type })
    hydration[name] = map
})

const codec = {
    json: (value) => {
        if (value === null || value === undefined) return null
        if (typeof value === 'string') {
            try {
                return JSON.parse(value)
            } catch {
                return null
            }
        }

        return value
    },
    bool: (value) => (value === null || value === undefined ? value : Boolean(Number(value)) || value === true),
    ts: (value) => {
        if (value === null || value === undefined) return null
        if (value instanceof Date) return value

        return new Date(value)
    },
    bigint: (value) => (value === null || value === undefined ? value : Number(value)),
}

/**
 * Serialize a value for storage.
 *
 * JSON columns must be stringified here rather than left to the drivers: the
 * sqlite driver stringifies objects, but node-postgres sends a JS *array* as a
 * Postgres array literal (and a plain object as garbage), so a rediscovered
 * role policy list or object tag map would be stored mangled on Postgres.
 * Doing it in one place keeps both dialects byte-identical.
 */
const encodeValue = (type, value) => {
    if (value === undefined) return null
    if (value === null) return null
    if (type === 'json' && typeof value === 'object' && !Buffer.isBuffer(value) && !(value instanceof Date)) {
        return JSON.stringify(value)
    }

    return value
}

/** Convert a raw DB row into a hydrated JS object. */
const hydrateRow = (table, row) => {
    if (!row) return row
    const map = hydration[table]
    if (!map) return row
    const out = {}
    Object.entries(row).forEach(([key, value]) => {
        const type = map[key]
        const decode = codec[type]
        out[key] = decode ? decode(value) : value
    })

    return out
}

const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Date)

class Repository {
    /**
     * @param {object} db driver handle from src/db
     * @param {object} [opts]
     */
    constructor(db, opts = {}) {
        this.db = db
        this.dialect = db.dialect
        this.opts = opts
    }

    /** Repo bound to a transaction. */
    withTx(db) {
        return new Repository(db, this.opts)
    }

    transaction(fn) {
        return this.db.transaction((tx) => fn(this.withTx(tx)))
    }

    assertTable(table) {
        if (!tables[table]) throw new Error(`Unknown table "${table}"`)
    }

    assertColumns(table, columns) {
        this.assertTable(table)
        columns.forEach((c) => {
            if (!tables[table].columns[c]) throw new Error(`Unknown column "${c}" on table "${table}"`)
        })
    }

    columns(table) {
        this.assertTable(table)

        return Object.keys(tables[table].columns)
    }

    /** Build a WHERE clause from a declarative filter object. */
    buildWhere(table, where = {}, params = []) {
        const clauses = []
        const push = (sql, values) => {
            clauses.push(sql)
            params.push(...values)
        }
        const handle = (key, value) => {
            if (key === 'or' || key === 'and') {
                const groups = (Array.isArray(value) ? value : [value]).map((sub) => {
                    const subParams = []
                    const sql = this.buildWhere(table, sub, subParams)
                    params.push(...subParams)

                    return `(${sql})`
                })
                if (groups.length) clauses.push(groups.join(key === 'or' ? ' or ' : ' and '))

                return
            }
            if (key === 'raw') {
                const [sql, values = []] = value
                push(`(${sql})`, values)

                return
            }
            if (key === 'not') {
                const subParams = []
                const sql = this.buildWhere(table, value, subParams)
                params.push(...subParams)
                push(`not (${sql})`, [])

                return
            }
            this.assertColumns(table, [key])
            if (value === null || value === undefined) {
                push(`"${key}" is null`, [])

                return
            }
            if (Array.isArray(value)) {
                if (!value.length) {
                    push('1 = 0', [])

                    return
                }
                push(`"${key}" in (${value.map(() => '?').join(', ')})`, value)

                return
            }
            if (isPlainObject(value)) {
                if ('in' in value) {
                    if (!value.in.length) {
                        push('1 = 0', [])

                        return
                    }
                    push(`"${key}" in (${value.in.map(() => '?').join(', ')})`, value.in)

                    return
                }
                if ('notIn' in value) {
                    if (!value.notIn.length) {
                        push('1 = 1', [])

                        return
                    }
                    push(`"${key}" not in (${value.notIn.map(() => '?').join(', ')})`, value.notIn)

                    return
                }
                if ('like' in value) {
                    push(`lower("${key}") like lower(?)`, [`%${value.like}%`])
                }
                if ('startsWith' in value) {
                    push(`lower("${key}") like lower(?)`, [`${value.startsWith}%`])
                }
                if ('raw' in value) {
                    push(`"${key}" ${value.raw}`, [])
                }
                Object.entries(OPERATORS).forEach(([op, sqlOp]) => {
                    if (op in value) push(`"${key}" ${sqlOp} ?`, [value[op]])
                })
                if ('is' in value) {
                    if (value.is === null) push(`"${key}" is null`, [])
                    else push(`"${key}" is ?`, [value.is])
                }
                // No recognised operator: compare the value as-is (the drivers
                // serialise plain objects to JSON, which is what a json column
                // stores). Silently dropping the condition here would turn a
                // targeted lookup into "match any row" - never do that.
                if (!Object.keys(value).some((opName) => OPERATORS[opName]
                    || ['in', 'notIn', 'like', 'startsWith', 'raw', 'is'].includes(opName))) {
                    push(`"${key}" = ?`, [value])
                }

                return
            }
            push(`"${key}" = ?`, [value])
        }
        Object.entries(where).forEach(([key, value]) => handle(key, value))

        return clauses.length ? clauses.join(' and ') : '1 = 1'
    }

    buildOrder(table, orderBy = []) {
        if (!orderBy || !orderBy.length) return ''
        const parts = orderBy.map((spec) => {
            const column = typeof spec === 'string' ? spec : spec.column
            const dir = (typeof spec === 'string' ? 'asc' : spec.dir || 'asc').toLowerCase()
            this.assertColumns(table, [column])
            if (!['asc', 'desc'].includes(dir)) throw new Error(`Invalid sort direction ${dir}`)

            return `"${column}" ${dir}`
        })

        return ` order by ${parts.join(', ')}`
    }

    buildLimit(opts = {}) {
        const { limit, offset } = opts
        if (limit === undefined && offset === undefined) return ''
        const sql = []
        if (limit !== undefined && limit !== null) sql.push('?')
        if (offset) sql.push('?')
        const params = []
        if (limit !== undefined && limit !== null) params.push(Number(limit))
        if (offset) params.push(Number(offset))

        return { sql: ` limit ${limit !== undefined && limit !== null ? '?' : '-1'}${offset ? ' offset ?' : ''}`, params }
    }

    async find(table, where = {}, opts = {}) {
        this.assertTable(table)
        const params = []
        const whereSql = this.buildWhere(table, where, params)
        const select = opts.select && opts.select.length ? opts.select : ['*']
        if (opts.select) this.assertColumns(table, opts.select)
        const sql = `select ${select.map((c) => (c === '*' ? '*' : `"${c}"`)).join(', ')} from "${table}" where ${whereSql}`
            + this.buildOrder(table, opts.orderBy)
        let finalSql = sql
        if (opts.limit !== undefined) {
            finalSql += ' limit ?'
            params.push(Number(opts.limit))
        }
        if (opts.offset) {
            finalSql += ' offset ?'
            params.push(Number(opts.offset))
        }
        const rows = await this.db.all(finalSql, params)

        return rows.map((r) => hydrateRow(table, r))
    }

    async findOne(table, where = {}, opts = {}) {
        const rows = await this.find(table, where, { ...opts, limit: 1 })

        return rows.length ? rows[0] : null
    }

    async count(table, where = {}) {
        const params = []
        const whereSql = this.buildWhere(table, where, params)
        const row = await this.db.get(`select count(*) as count from "${table}" where ${whereSql}`, params)

        return Number(row ? row.count : 0)
    }

    async exists(table, where = {}) {
        const params = []
        const whereSql = this.buildWhere(table, where, params)
        const row = await this.db.get(`select 1 as found from "${table}" where ${whereSql} limit 1`, params)

        return !!row
    }

    /** Aggregate helper: sum/avg/min/max over a column with a filter. */
    async aggregate(table, fn, column, where = {}) {
        this.assertColumns(table, [column])
        if (!['sum', 'avg', 'min', 'max'].includes(fn)) throw new Error(`Invalid aggregate ${fn}`)
        const params = []
        const whereSql = this.buildWhere(table, where, params)
        const row = await this.db.get(`select ${fn}("${column}") as value from "${table}" where ${whereSql}`, params)

        return row ? row.value : null
    }

    /** Build defaults for a row based on the schema. */
    prepareInsert(table, row) {
        this.assertTable(table)
        const defs = tables[table].columns
        const columns = Object.keys(defs)
        const out = { ...row }
        columns.forEach((col) => {
            const def = defs[col]
            if (out[col] === undefined) {
                if (def.default === 'UUID') out[col] = randomUUID()
                else if (def.default === 'NOW') out[col] = new Date()
                else if (def.default !== undefined && def.type !== 'serial') out[col] = def.default
            }
            if (def.type === 'serial') delete out[col]
            if (out[col] !== undefined) out[col] = encodeValue(def.type, out[col])
        })

        return out
    }

    async insert(table, row) {
        this.assertTable(table)
        const prepared = this.prepareInsert(table, row)
        const columns = Object.keys(prepared)
        this.assertColumns(table, columns)
        const sql = `insert into "${table}" (${columns.map((c) => `"${c}"`).join(', ')}) `
            + `values (${columns.map(() => '?').join(', ')})`
        try {
            await this.db.run(sql, columns.map((c) => prepared[c]))
        } catch (err) {
            if (/unique/i.test(err.message)) {
                err.code = 'DUPLICATE'
                err.statusCode = 409
            }
            throw err
        }

        return hydrateRow(table, prepared)
    }

    /** Insert many rows in one statement (chunked to stay under param limits). */
    async insertMany(table, rows) {
        if (!rows.length) return []
        const inserted = []
        const chunkSize = 200
        for (let i = 0; i < rows.length; i += chunkSize) {
            const chunk = rows.slice(i, i + chunkSize)
            const prepared = chunk.map((r) => this.prepareInsert(table, r))
            const columns = Object.keys(prepared[0])
            this.assertColumns(table, columns)
            const values = []
            const placeholders = prepared.map((row) => {
                values.push(...columns.map((c) => row[c]))

                return `(${columns.map(() => '?').join(', ')})`
            })
            // eslint-disable-next-line no-await-in-loop
            await this.db.run(
                `insert into "${table}" (${columns.map((c) => `"${c}"`).join(', ')}) values ${placeholders.join(', ')}`,
                values,
            )
            inserted.push(...prepared.map((r) => hydrateRow(table, r)))
        }

        return inserted
    }

    async update(table, where, patch) {
        this.assertTable(table)
        const prepared = { ...patch }
        if (tables[table].columns.updatedAt && prepared.updatedAt === undefined) prepared.updatedAt = new Date()
        const columns = Object.keys(prepared)
        this.assertColumns(table, columns)
        if (!columns.length) return 0
        const params = []
        const setSql = columns.map((c) => {
            params.push(encodeValue(tables[table].columns[c].type, prepared[c]))

            return `"${c}" = ?`
        }).join(', ')
        const whereSql = this.buildWhere(table, where, params)
        const res = await this.db.run(`update "${table}" set ${setSql} where ${whereSql}`, params)

        return res.changes
    }

    async delete(table, where) {
        this.assertTable(table)
        const params = []
        const whereSql = this.buildWhere(table, where, params)
        const res = await this.db.run(`delete from "${table}" where ${whereSql}`, params)

        return res.changes
    }

    /** Raw escape hatch for reporting queries written by hand. */
    all(sql, params) {
        return this.db.all(sql, params)
    }

    get(sql, params) {
        return this.db.get(sql, params)
    }

    run(sql, params) {
        return this.db.run(sql, params)
    }
}

module.exports = { Repository, hydrateRow, encodeValue }
