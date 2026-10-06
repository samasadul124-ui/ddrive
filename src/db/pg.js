/**
 * Postgres driver (production).
 *
 * Uses knex purely as a connection pool + parameter binding layer. All SQL is
 * written in the repository with `?` placeholders, which knex binds safely for
 * the pg client.
 */
const Knex = require('knex')

const wrap = (client) => ({
    dialect: 'pg',
    async all(sql, params = []) {
        const res = await client.raw(sql, params)

        return res.rows || []
    },
    async get(sql, params = []) {
        const rows = await this.all(sql, params)

        return rows.length ? rows[0] : null
    },
    async run(sql, params = []) {
        const res = await client.raw(sql, params)

        return { changes: res.rowCount || 0, rows: res.rows || [] }
    },
    async exec(sql) {
        await client.raw(sql)
    },
})

const createPgDb = (config = {}) => {
    const knex = Knex({
        client: 'pg',
        connection: config.connection,
        pool: config.pool || { min: 2, max: 10 },
        acquireConnectionTimeout: config.acquireConnectionTimeout || 15000,
    })

    const base = wrap(knex)

    return {
        ...base,
        knex,
        async transaction(fn) {
            return knex.transaction(async (trx) => fn({ ...base, ...wrap(trx), knex: trx }))
        },
        async close() {
            await knex.destroy()
        },
    }
}

module.exports = { createPgDb }
