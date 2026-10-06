/**
 * Prometheus metrics registry.
 *
 * Counters and summaries are cheap in-process structures; gauges can be backed
 * by async callbacks (database counts, replication backlog, ...) evaluated at
 * scrape time with a small cache so a scrape never hammers the database.
 */
const createMetrics = (deps = {}) => {
    const { prefix = 'ddrive', logger = console, gaugeTtlMs = 15000 } = deps
    const counters = new Map()
    const summaries = new Map()
    const gauges = new Map()
    const values = new Map()
    let startTime = Date.now()

    const labelKey = (labels = {}) => Object.entries(labels)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([k, v]) => `${k}="${String(v).replace(/"/g, '')}"`)
        .join(',')

    const name = (metric) => {
        const base = metric.startsWith(`${prefix}_`) ? metric : `${prefix}_${metric}`

        return base.replace(/[^a-zA-Z0-9_:]/g, '_')
    }

    const inc = (metric, value = 1, labels = {}) => {
        const key = `${metric}{${labelKey(labels)}}`
        const current = counters.get(key) || { metric, labels, value: 0 }
        current.value += Number(value) || 0
        counters.set(key, current)
    }

    const observe = (metric, ms, labels = {}) => {
        const key = `${metric}{${labelKey(labels)}}`
        const current = summaries.get(key) || { metric, labels, sum: 0, count: 0 }
        current.sum += Number(ms) || 0
        current.count += 1
        summaries.set(key, current)
    }

    const gauge = (metric, fn, labels = {}) => {
        gauges.set(`${metric}{${labelKey(labels)}}`, { metric, labels, fn, cachedAt: 0, value: null })
    }

    const setGauge = (metric, value, labels = {}) => {
        values.set(`${metric}{${labelKey(labels)}}`, { metric, labels, value })
    }

    const render = async () => {
        const lines = []
        const emitted = new Set()
        const emitType = (metric) => {
            if (!emitted.has(metric)) {
                emitted.add(metric)
                lines.push(`# HELP ${name(metric)} DDrive metric ${metric}`)
                lines.push(`# TYPE ${name(metric)} ${metric.endsWith('_total') ? 'counter' : 'gauge'}`)
            }
        }

        for (const entry of counters.values()) {
            emitType(entry.metric)
            lines.push(`${name(entry.metric)}${entry.labels && Object.keys(entry.labels).length ? `{${labelKey(entry.labels)}}` : ''} ${entry.value}`)
        }
        for (const entry of summaries.values()) {
            emitType(entry.metric)
            const labels = labelKey(entry.labels)
            const suffix = labels ? `{${labels}}` : ''
            lines.push(`${name(entry.metric)}_sum${suffix} ${entry.sum}`)
            lines.push(`${name(entry.metric)}_count${suffix} ${entry.count}`)
        }
        for (const entry of values.values()) {
            emitType(entry.metric)
            lines.push(`${name(entry.metric)}${Object.keys(entry.labels).length ? `{${labelKey(entry.labels)}}` : ''} ${entry.value}`)
        }
        for (const entry of gauges.values()) {
            if (Date.now() - entry.cachedAt > gaugeTtlMs) {
                try {
                    // eslint-disable-next-line no-await-in-loop
                    entry.value = await entry.fn()
                    entry.cachedAt = Date.now()
                } catch (err) {
                    logger.warn?.({ err, metric: entry.metric }, 'gauge evaluation failed')
                    entry.value = Number.NaN
                }
            }
            emitType(entry.metric)
            lines.push(`${name(entry.metric)}${Object.keys(entry.labels).length ? `{${labelKey(entry.labels)}}` : ''} ${Number.isFinite(entry.value) ? entry.value : 0}`)
        }
        lines.push(`# HELP ${name('uptime_seconds')} Process uptime in seconds`)
        lines.push(`# TYPE ${name('uptime_seconds')} gauge`)
        lines.push(`${name('uptime_seconds')} ${Math.round((Date.now() - startTime) / 1000)}`)

        return `${lines.join('\n')}\n`
    }

    /** Fastify hook: request counters + latency summary. */
    const fastifyPlugin = async (fastify) => {
        fastify.addHook('onResponse', async (req, reply) => {
            const route = req.routeOptions?.url || req.routerPath || req.url || 'unknown'
            const labels = { protocol: req.ddrive?.protocol || 'rest', method: req.method, route, status: reply.statusCode }
            inc('http_requests_total', 1, labels)
            observe('http_request_duration_ms', reply.elapsedTime || 0, { protocol: labels.protocol, method: req.method, route })
        })
    }

    const snapshot = () => ({
        counters: [...counters.values()].map((c) => ({ ...c })),
        summaries: [...summaries.values()].map((c) => ({ ...c })),
        gauges: [...gauges.values()].map((g) => ({ metric: g.metric, labels: g.labels, value: g.value })),
        values: [...values.values()].map((v) => ({ ...v })),
        uptimeSeconds: Math.round((Date.now() - startTime) / 1000),
    })

    const reset = () => {
        counters.clear()
        summaries.clear()
        startTime = Date.now()
    }

    return {
        inc, observe, gauge, setGauge, render, fastifyPlugin, snapshot, reset, labelKey,
    }
}

module.exports = { createMetrics }
