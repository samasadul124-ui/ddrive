/**
 * Operational endpoints: health, readiness, Prometheus metrics and the
 * internal replication API used between DDrive nodes.
 */
const util = require('../lib/util')
const { errors } = require('../lib/errors')

const registerMonitoring = (fastify, context, deps) => {
    const {
        metrics, replication, config,
    } = context
    const { auth } = deps

    if (config.servers.health.enabled !== false) {
        fastify.get('/healthz', async (req, reply) => {
            const result = await context.health()
            reply.code(result.status === 'ok' ? 200 : 503)

            return result
        })
        fastify.get('/readyz', async (req, reply) => {
            const result = await context.health()
            const storage = Object.values(result.storage || {})
            const ready = result.database.ok && storage.every((entry) => entry.ok !== false)
            reply.header('content-type', 'text/plain')
            reply.code(ready ? 200 : 503)

            return ready ? 'ready\n' : 'not-ready\n'
        })
    }

    if (config.servers.metrics.enabled !== false) {
        fastify.get('/metrics', async (req, reply) => {
            const principal = await auth.requirePrincipal(req, reply)
            await auth.authorize(req, principal, 'ddrive:ReadMetrics', {})
            reply.header('content-type', 'text/plain; version=0.0.4; charset=utf-8')

            return metrics.render()
        })
    }

    // ------------------------------------------------------------------
    // Internal replication API (node to node, HMAC signed)
    // ------------------------------------------------------------------
    fastify.get('/_internal/replication/health', async () => ({
        ok: true,
        node: config.node.name,
        region: config.node.region,
        version: context.VERSION,
        time: util.iso(new Date()),
    }))

    const applyIncoming = async (req) => {
        const body = await util.readBody(req, { limit: config.replication?.maxBodyBytes || 512 * 1024 * 1024 })
        const result = await replication.applyIncoming(req.headers, body)
        req.ddrive.principal = context.iam.anonymousPrincipal()
        req.ddrive.replication = true

        return result
    }

    fastify.post('/_internal/replication/objects', async (req, reply) => {
        const result = await applyIncoming(req)
        reply.code(200)

        return result
    })

    fastify.delete('/_internal/replication/objects', async (req, reply) => {
        if (!req.headers['x-ddrive-meta']) throw errors.invalidArgument('x-ddrive-meta header is required')
        const result = await replication.applyIncoming(req.headers, Buffer.alloc(0))
        reply.code(200)

        return result
    })

    // ------------------------------------------------------------------
    // Manual maintenance triggers for operators and the test suite
    // ------------------------------------------------------------------
    fastify.post('/_internal/maintenance/:task', async (req, reply) => {
        const principal = await auth.requirePrincipal(req, reply)
        req.ddrive.principal = principal
        const { task } = req.params
        const { bucket, query } = req

        if (task === 'lifecycle') {
            await auth.authorize(req, principal, 'ddrive:RunLifecycle', {})
            const target = bucket ? await context.buckets.get(bucket) : null

            return context.lifecycle.run({ bucket: target, dryRun: String(query.dryRun || '') === 'true' })
        }
        if (task === 'tiering') {
            await auth.authorize(req, principal, 'ddrive:ManageTiering', {})
            const target = bucket ? await context.buckets.get(bucket) : null

            return context.tiering.run({ bucket: target, dryRun: String(query.dryRun || '') === 'true' })
        }
        if (task === 'replication') {
            await auth.authorize(req, principal, 'ddrive:ManageReplication', {})

            return { processed: await context.replication.processDue(Number(query.limit || 50)) }
        }
        if (task === 'events') {
            await auth.authorize(req, principal, 'ddrive:RedriveEvents', {})

            return { delivered: await context.events.processDue() }
        }
        if (task === 'audit-prune') {
            await auth.authorize(req, principal, 'ddrive:WriteSettings', {})

            return context.audit.prune(Number(query.days || config.audit.retentionDays || 0))
        }
        if (task === 'multipart-abort') {
            await auth.authorize(req, principal, 'ddrive:ManageLifecycle', {})

            return { aborted: await context.objects.abortStaleUploads(Number(query.days || config.workers.multipartTtlDays)) }
        }
        if (task === 'audit-verify') {
            await auth.authorize(req, principal, 'ddrive:VerifyAudit', {})

            return context.audit.verify()
        }

        throw errors.invalidArgument(`Unknown maintenance task ${task}`)
    })
}

module.exports = { registerMonitoring }
