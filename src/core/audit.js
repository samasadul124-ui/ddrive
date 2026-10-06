/**
 * Tamper evident audit log.
 *
 * Every event is appended to `audit_event` with a SHA-256 hash chain
 * (`hash = sha256(prevHash + canonicalJson(event))`), so any modification or
 * removal of a historical record is detectable by re-walking the chain
 * (`audit.verify()`), satisfying the "encryption / access audit log" and legal
 * hold evidence requirements.
 *
 * Sinks: the database is the source of truth; optional append-only JSONL file
 * (`AUDIT_LOG_FILE`), webhook (`AUDIT_WEBHOOK_URL`) and syslog UDP fan-out.
 */
const fs = require('fs')
const fsp = require('fs/promises')
const dgram = require('dgram')
const path = require('path')
const { randomUUID } = require('crypto')
const util = require('../lib/util')

const GENESIS_HASH = 'GENESIS'

const createAudit = (deps = {}) => {
    const {
        repo, logger = console, file, webhookUrl, syslogHost, syslogPort = 514, retentionDays,
    } = deps
    if (!repo) throw new Error('audit requires a repository')

    let queue = Promise.resolve()
    let lastHashCache = null

    const computeHash = (prevHash, payload) => util.sha256(`${prevHash}|${util.canonicalJson(payload)}`)

    /** Serialize chain appends across concurrent requests (and across nodes on Postgres). */
    const withChainLock = async (fn) => {
        if (repo.dialect === 'pg') {
            return repo.transaction(async (tx) => {
                // xact advisory lock: released automatically at commit
                await tx.all('select pg_advisory_xact_lock(?)', [0xdd01])

                return fn(tx)
            })
        }
        const run = queue.then(() => fn(repo), () => fn(repo))
        queue = run.then(() => undefined, () => undefined)

        return run
    }

    const sinks = []
    if (file) {
        const target = path.resolve(file)
        fs.mkdirSync(path.dirname(target), { recursive: true })
        sinks.push(async (event) => { await fsp.appendFile(target, `${JSON.stringify(event)}\n`) })
    }
    if (webhookUrl) {
        sinks.push(async (event) => {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify(event),
                signal: AbortSignal.timeout(5000),
            })
        })
    }
    if (syslogHost) {
        const socket = dgram.createSocket('udp4')
        sinks.push(async (event) => {
            const msg = Buffer.from(`${new Date().toISOString()} ddrive-audit ${JSON.stringify(event)}`)
            await new Promise((resolve) => socket.send(msg, syslogPort, syslogHost, () => resolve()))
        })
    }

    const fanOut = (event) => {
        sinks.forEach((sink) => {
            sink(event).catch((err) => logger.warn?.({ err }, 'audit sink failed'))
        })
    }

    /**
     * Append an audit record.
     * @param {object} input
     */
    const record = async (input) => {
        const base = {
            id: randomUUID(),
            ts: input.ts ? new Date(input.ts) : new Date(),
            actor: input.actor || null,
            actorId: input.actorId || null,
            actorType: input.actorType || null,
            action: input.action,
            resource: input.resource || null,
            resourceType: input.resourceType || null,
            bucket: input.bucket || null,
            bucketId: input.bucketId || null,
            objectKey: input.objectKey || null,
            versionId: input.versionId || null,
            result: input.result || 'success',
            statusCode: input.statusCode || null,
            ip: input.ip || null,
            userAgent: input.userAgent || null,
            requestId: input.requestId || null,
            protocol: input.protocol || null,
            detail: input.detail || null,
        }
        if (!base.action) throw new Error('audit record requires an action')

        try {
            return await withChainLock(async (tx) => {
                let prevHash = lastHashCache
                if (!prevHash) {
                    const last = await tx.get('select "hash" from "audit_event" order by "seq" desc limit 1')
                    prevHash = last && last.hash ? last.hash : GENESIS_HASH
                }
                // Hash exactly the shape that will be stored. `undefined` becomes
                // `null` in the canonical form but is dropped by the database, so
                // hashing the raw input would produce a chain that cannot verify.
                const payload = JSON.parse(util.canonicalJson({ ...base, ts: util.iso(base.ts) }))
                const hash = computeHash(prevHash, payload)
                const row = await tx.insert('audit_event', { ...payload, ts: base.ts, prevHash, hash })
                lastHashCache = hash
                fanOut({ ...payload, prevHash, hash })

                return row
            })
        } catch (err) {
            // Auditing must never break the data plane, but it must be loud.
            logger.error?.({ err, action: base.action }, 'failed to write audit event')

            return null
        }
    }

    /**
     * Re-walk the hash chain. Detects edits, deletions and reordering.
     * @param {object} [opts] { from, to, limit }
     */
    const verify = async (opts = {}) => {
        const limit = Math.min(opts.limit || 100000, 1000000)
        const rows = await repo.find('audit_event', {}, { orderBy: [{ column: 'seq', dir: 'asc' }], limit })
        let prevHash = GENESIS_HASH
        let checked = 0
        for (const row of rows) {
            const payload = JSON.parse(util.canonicalJson({
                id: row.id,
                ts: util.iso(row.ts),
                actor: row.actor,
                actorId: row.actorId,
                actorType: row.actorType,
                action: row.action,
                resource: row.resource,
                resourceType: row.resourceType,
                bucket: row.bucket,
                bucketId: row.bucketId,
                objectKey: row.objectKey,
                versionId: row.versionId,
                result: row.result,
                statusCode: row.statusCode,
                ip: row.ip,
                userAgent: row.userAgent,
                requestId: row.requestId,
                protocol: row.protocol,
                detail: row.detail,
            }))
            const expected = computeHash(prevHash, payload)
            if (row.prevHash !== prevHash || row.hash !== expected) {
                return {
                    ok: false,
                    checked,
                    brokenAt: { seq: row.seq, id: row.id, expected, actual: row.hash },
                }
            }
            prevHash = row.hash
            checked += 1
        }

        return { ok: true, checked, head: prevHash }
    }

    const query = async (filters = {}) => {
        const where = {}
        if (filters.action) where.action = { like: filters.action }
        if (filters.actor) where.actor = filters.actor
        if (filters.bucket) where.bucket = filters.bucket
        if (filters.result) where.result = filters.result
        if (filters.from) where.ts = { ...(where.ts || {}), gte: new Date(filters.from) }
        if (filters.to) where.ts = { ...(where.ts || {}), lte: new Date(filters.to) }
        if (filters.objectKey) where.objectKey = { like: filters.objectKey }

        const limit = Math.min(filters.limit || 100, 1000)
        const offset = filters.offset || 0
        // `encrypted=true|false` narrows to events that carry the encryption
        // envelope detail (algorithm / key id / envelope mode). The detail is a
        // JSON column, so the scan happens in memory and pagination is applied
        // after filtering.
        const wantsEncryption = filters.encrypted !== undefined && filters.encrypted !== null && filters.encrypted !== ''
        const rows = await repo.find('audit_event', where, {
            orderBy: [{ column: 'seq', dir: 'desc' }],
            limit: wantsEncryption ? 1000 : limit,
            offset: wantsEncryption ? 0 : offset,
        })
        if (!wantsEncryption) return rows

        const want = filters.encrypted === true || filters.encrypted === 'true'
        const filtered = rows.filter((row) => {
            const enc = row.detail && row.detail.encryption
            if (!want) return !enc || enc.enabled !== true
            return Boolean(enc) && enc.enabled === true
        })

        return filtered.slice(offset, offset + limit)
    }

    const stats = async () => {
        const [total, latest] = await Promise.all([
            repo.count('audit_event'),
            repo.findOne('audit_event', {}, { orderBy: [{ column: 'seq', dir: 'desc' }] }),
        ])
        const byAction = await repo.all('select "action", count(*) as count from "audit_event" group by "action" order by count desc limit 20')

        return {
            total, byAction: byAction.map((r) => ({ action: r.action, count: Number(r.count) })), latest,
        }
    }

    /** Prune records older than the retention window (records the prune itself). */
    const prune = async (days = retentionDays) => {
        if (!days) return { pruned: 0 }
        const cutoff = util.addDays(new Date(), -days)
        const count = await repo.delete('audit_event', { ts: { lt: cutoff } })
        if (count) {
            await record({
                action: 'audit.prune',
                actor: 'system',
                actorType: 'system',
                resource: 'audit_event',
                result: 'success',
                detail: { cutoff: util.iso(cutoff), pruned: count, retentionDays: days },
            })
        }

        return { pruned: count }
    }

    /**
     * Compliance roll-up of the encryption side of the audit trail: how many
     * object writes were encrypted end to end, with which algorithm and key,
     * broken down per bucket. Reads `object.put` events only.
     */
    const encryptionSummary = async (filters = {}) => {
        const where = { action: 'object.put' }
        if (filters.bucket) where.bucket = filters.bucket
        if (filters.from) where.ts = { ...(where.ts || {}), gte: new Date(filters.from) }
        if (filters.to) where.ts = { ...(where.ts || {}), lte: new Date(filters.to) }

        const rows = await repo.find('audit_event', where, {
            orderBy: [{ column: 'seq', dir: 'desc' }], limit: 5000,
        })
        const algorithms = new Map()
        const keys = new Map()
        const buckets = new Map()
        let encrypted = 0
        let plaintext = 0
        let lastEncryptedAt = null

        rows.forEach((row) => {
            const enc = (row.detail && row.detail.encryption) || {}
            const bucket = row.bucket || '(none)'
            if (!buckets.has(bucket)) buckets.set(bucket, { bucket, encrypted: 0, plaintext: 0 })
            const entry = buckets.get(bucket)
            if (enc.enabled === true) {
                encrypted += 1
                entry.encrypted += 1
                const algorithm = enc.algorithm || 'unknown'
                algorithms.set(algorithm, (algorithms.get(algorithm) || 0) + 1)
                const keyId = enc.keyId || 'unknown'
                keys.set(keyId, (keys.get(keyId) || 0) + 1)
                if (!lastEncryptedAt) lastEncryptedAt = util.iso(row.ts)
            } else {
                plaintext += 1
                entry.plaintext += 1
            }
        })

        return {
            scanned: rows.length,
            encrypted,
            plaintext,
            encryptedRatio: rows.length ? Number((encrypted / rows.length).toFixed(4)) : null,
            algorithms: [...algorithms.entries()].map(([algorithm, count]) => ({ algorithm, count })),
            keys: [...keys.entries()].map(([keyId, count]) => ({ keyId, count })),
            buckets: [...buckets.values()].sort((a, b) => (b.encrypted + b.plaintext) - (a.encrypted + a.plaintext)),
            lastEncryptedAt,
        }
    }

    const exportCsv = async (filters = {}) => {
        const rows = await query({ ...filters, limit: 1000 })
        const header = [
            'seq', 'ts', 'actor', 'actorType', 'action', 'bucket', 'key', 'versionId',
            'result', 'statusCode', 'encryption', 'algorithm', 'keyId', 'detail', 'ip', 'requestId',
        ].join(',')
        const lines = rows.map((r) => {
            const enc = (r.detail && r.detail.encryption) || {}
            const cells = [
                r.seq, util.iso(r.ts), r.actor, r.actorType, r.action, r.bucket, r.objectKey, r.versionId,
                r.result, r.statusCode,
                enc.enabled === undefined ? '' : enc.enabled,
                enc.algorithm || '', enc.keyId || '',
                r.detail ? JSON.stringify(r.detail) : '',
                r.ip, r.requestId,
            ]

            return cells.map((v) => `"${String(v === null || v === undefined ? '' : v).replace(/"/g, '""')}"`).join(',')
        })

        return [header, ...lines].join('\n')
    }

    return {
        record, verify, query, stats, prune, exportCsv, encryptionSummary, GENESIS_HASH, sinks: sinks.length,
    }
}

module.exports = { createAudit, GENESIS_HASH }
