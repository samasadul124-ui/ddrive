/**
 * DDL generation from the declarative schema (see ./schema.js).
 *
 * Emits portable SQL for the `pg` and `sqlite` dialects so a single schema
 * definition can bootstrap both a production Postgres cluster and a
 * single-node embedded SQLite deployment.
 */
const { tables } = require('./schema')

const DIALECT_TYPES = {
    pg: {
        uuid: 'uuid',
        text: 'text',
        int: 'integer',
        bigint: 'bigint',
        bool: 'boolean',
        json: 'jsonb',
        ts: 'timestamptz',
        serial: 'bigserial',
    },
    sqlite: {
        uuid: 'text',
        text: 'text',
        int: 'integer',
        bigint: 'integer',
        bool: 'integer',
        json: 'text',
        ts: 'text',
        serial: 'integer',
    },
}

const DEFAULT_SQL = {
    pg: { UUID: 'gen_random_uuid()', NOW: 'now()' },
    sqlite: { UUID: null, NOW: 'CURRENT_TIMESTAMP' },
}

const columnSql = (dialect, name, col) => {
    const type = DIALECT_TYPES[dialect][col.type] || 'text'
    const parts = [`"${name}"`, type]
    if (col.primary && col.type === 'serial' && dialect === 'sqlite') {
        return `"${name}" integer primary key autoincrement`
    }
    if (col.primary) parts.push('primary key')
    if (col.notNull) parts.push('not null')
    if (col.unique) parts.push('unique')
    if (col.default !== undefined) {
        if (col.default === 'UUID' || col.default === 'NOW') {
            const def = DEFAULT_SQL[dialect][col.default]
            if (def) parts.push(`default ${def}`)
        } else if (typeof col.default === 'boolean') {
            parts.push(`default ${col.default ? 'true' : 'false'}`)
        } else if (typeof col.default === 'number') {
            parts.push(`default ${col.default}`)
        } else {
            parts.push(`default '${String(col.default).replace(/'/g, "''")}'`)
        }
    }
    return parts.join(' ')
}

const createTable = (dialect, tableName) => {
    const table = tables[tableName]
    if (!table) throw new Error(`Unknown table ${tableName}`)
    const cols = Object.entries(table.columns).map(([name, col]) => columnSql(dialect, name, col))
    const constraints = (table.uniques || []).map(
        (u) => `constraint "${u.name}" unique (${u.columns.map((c) => `"${c}"`).join(', ')})`,
    )
    const body = [...cols, ...constraints].join(',\n    ')
    return `create table if not exists "${tableName}" (\n    ${body}\n)`
}

const createIndexes = (dialect, tableName) => {
    const table = tables[tableName]
    return (table.indexes || []).map(
        (i) => `create index if not exists "${i.name}" on "${tableName}" (${i.columns.map((c) => `"${c}"`).join(', ')})`,
    )
}

/**
 * Returns DDL statements creating every table + index for the given dialect.
 * @param {'pg'|'sqlite'} dialect
 * @param {{ only?: string[], skip?: string[] }} [opts]
 */
const schemaDDL = (dialect, opts = {}) => {
    if (!DIALECT_TYPES[dialect]) throw new Error(`Unsupported dialect ${dialect}`)
    let names = Object.keys(tables)
    if (opts.only) names = names.filter((n) => opts.only.includes(n))
    if (opts.skip) names = names.filter((n) => !opts.skip.includes(n))
    const stmts = []
    names.forEach((n) => {
        stmts.push(createTable(dialect, n))
        stmts.push(...createIndexes(dialect, n))
    })

    return stmts
}

module.exports = { schemaDDL, DIALECT_TYPES }
