/**
 * Automatic classification / tagging.
 *
 * Two cooperating layers:
 *
 *  1. **AI tagger** (`AI_TAGGER_URL`) - when configured, the first bytes of the
 *     object are sent to a model endpoint which returns tags + confidence:
 *        POST { url } { name, contentType, size, sample: base64 }
 *        ->  { tags: { category: "invoice" }, confidence: 0.93 }
 *     Any OpenAI-compatible, Bedrock, Vertex or self-hosted endpoint can be
 *     wrapped in this tiny contract (see docs/ai-tagging.md).
 *
 *  2. **Heuristic classifier** - always available and used as a fallback (and
 *     as the "sensitive data" detector): sniffs magic bytes, mime type,
 *     extension and content patterns (JSON/CSV/XML/source/PII/secrets).
 *
 * Both feed `auto_tag_rule` rules which materialise tags onto objects; tags can
 * then drive lifecycle, tiering, replication and search.
 */
const util = require('../lib/util')
const { errors } = require('../lib/errors')

const MAX_SAMPLE = 8192

const MAGIC = [
    { tag: 'image', mime: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
    { tag: 'image', mime: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47] },
    { tag: 'image', mime: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38] },
    { tag: 'image', mime: 'image/webp', bytes: [0x52, 0x49, 0x46, 0x46] },
    { tag: 'archive', mime: 'application/zip', bytes: [0x50, 0x4b, 0x03, 0x04] },
    { tag: 'document', mime: 'application/pdf', bytes: [0x25, 0x50, 0x44, 0x46] },
    { tag: 'video', mime: 'video/mp4', bytes: [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70] },
    { tag: 'audio', mime: 'audio/mpeg', bytes: [0x49, 0x44, 0x33] },
    { tag: 'archive', mime: 'application/gzip', bytes: [0x1f, 0x8b] },
]

const PII_PATTERNS = [
    { key: 'email', regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ },
    { key: 'credit_card', regex: /\b(?:\d[ -]*?){13,16}\b/ },
    { key: 'iban', regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/ },
    { key: 'ssn_us', regex: /\b\d{3}-\d{2}-\d{4}\b/ },
    { key: 'phone', regex: /\+\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/ },
]

const SECRET_PATTERNS = [
    { key: 'aws_access_key', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
    { key: 'private_key', regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
    { key: 'jwt', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
    { key: 'password_field', regex: /(?:password|passwd|secret)\s*[:=]\s*\S{6,}/i },
]

const SOURCE_EXTENSIONS = new Set([
    '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.c', '.h', '.cpp',
    '.cs', '.php', '.sh', '.sql', '.yaml', '.yml', '.toml', '.tf', '.pl', '.lua', '.swift', '.scala',
])

const TEXT_EXTENSIONS = new Set(['.txt', '.md', '.log', '.csv', '.tsv', '.json', '.xml', '.html', '.css', '.ini', '.conf', '.env'])

const sniffMagic = (sample) => MAGIC.find((entry) => entry.bytes.every((byte, i) => sample[i] === byte))

const looksLikeText = (sample) => {
    const slice = sample.subarray(0, 512)
    let printable = 0
    for (const byte of slice) {
        if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127)) printable += 1
        else if (byte > 127) printable += 0.5
    }

    return slice.length && printable / slice.length > 0.85
}

/**
 * Offline classifier used when no AI endpoint is configured (and always used
 * for the sensitive-data / secret detection pass).
 * @returns {{ tags: object, confidence: number, engine: string }}
 */
const classify = ({ name, contentType, size, sample }) => {
    const tags = {}
    const ext = String(name || '').toLowerCase().slice(String(name || '').lastIndexOf('.') === -1 ? undefined : String(name).lastIndexOf('.'))
    const mime = String(contentType || '').split(';')[0].trim() || util.contentTypeOf(name)
    let confidence = 0.6

    const magic = sample && sample.length ? sniffMagic(sample) : null
    if (magic) {
        tags.category = magic.tag
        tags.mime = magic.mime
        confidence = 0.95
    } else if (mime.startsWith('image/')) {
        tags.category = 'image'
        confidence = 0.9
    } else if (mime.startsWith('video/')) {
        tags.category = 'video'
        confidence = 0.9
    } else if (mime.startsWith('audio/')) {
        tags.category = 'audio'
        confidence = 0.9
    } else if (mime.startsWith('text/') || TEXT_EXTENSIONS.has(ext) || (sample && looksLikeText(sample))) {
        tags.category = 'text'
        confidence = 0.75
    } else {
        tags.category = 'binary'
        confidence = 0.5
    }
    if (SOURCE_EXTENSIONS.has(ext)) {
        tags.category = 'source-code'
        tags.language = ext.slice(1)
        confidence = 0.9
    }
    if (ext === '.csv' || ext === '.tsv') tags.format = 'tabular'
    if (ext === '.json') tags.format = 'json'
    if (ext === '.xml') tags.format = 'xml'
    if (ext === '.pdf') tags.category = 'document'
    if (['.doc', '.docx', '.odt', '.rtf'].includes(ext)) tags.category = 'document'
    if (['.xls', '.xlsx', '.ods'].includes(ext)) { tags.category = 'spreadsheet'; tags.format = 'tabular' }
    if (['.zip', '.tar', '.gz', '.7z', '.rar', '.xz'].includes(ext)) tags.category = 'archive'
    if (['.iso', '.img', '.vhd', '.qcow2'].includes(ext)) tags.category = 'disk-image'
    if (['.db', '.sqlite', '.sqlite3', '.dump', '.bak'].includes(ext)) tags.category = 'database'
    if (['.tfstate', '.pem', '.key', '.p12', '.pfx'].includes(ext)) { tags.category = 'secret-material'; tags.sensitive = 'true' }

    if (sample && sample.length) {
        const text = sample.toString('utf8')
        const pii = PII_PATTERNS.filter((p) => p.regex.test(text)).map((p) => p.key)
        const secrets = SECRET_PATTERNS.filter((p) => p.regex.test(text)).map((p) => p.key)
        if (pii.length) {
            tags.pii = pii.join(',')
            tags.sensitive = 'true'
            confidence = Math.max(confidence, 0.85)
        }
        if (secrets.length) {
            tags.secrets = secrets.join(',')
            tags.sensitive = 'true'
            confidence = Math.max(confidence, 0.9)
        }
    }
    if (size !== undefined && size !== null) tags.size_class = size > 1024 ** 3 ? 'huge' : size > 100 * 1024 ** 2 ? 'large' : size > 1024 ** 2 ? 'medium' : 'small'

    return { tags, confidence, engine: 'heuristic' }
}

const createTagger = (deps = {}) => {
    const {
        repo, objects, audit, logger = console, aiUrl, aiToken, aiTimeoutMs = 8000, aiMinConfidence = 0.5,
    } = deps

    const enabled = () => !!aiUrl

    /** Ask the configured AI endpoint to classify the sample. */
    const classifyWithAi = async (input) => {
        if (!aiUrl) return null
        try {
            const res = await fetch(aiUrl, {
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    ...(aiToken ? { authorization: `Bearer ${aiToken}` } : {}),
                },
                body: JSON.stringify({
                    name: input.name,
                    contentType: input.contentType,
                    size: input.size,
                    sample: input.sample ? input.sample.toString('base64') : null,
                }),
                signal: AbortSignal.timeout(aiTimeoutMs),
            })
            if (!res.ok) throw new Error(`AI tagger responded ${res.status}`)
            const json = await res.json()
            if (!json || typeof json.tags !== 'object') throw new Error('AI tagger returned no tags')

            return { tags: json.tags, confidence: Number(json.confidence ?? 0.8), engine: json.engine || 'ai' }
        } catch (err) {
            logger.warn?.({ err }, 'AI tagging failed, falling back to the heuristic classifier')

            return null
        }
    }

    const readSample = async (bucket, node, size = MAX_SAMPLE) => {
        try {
            const { version } = await objects.getVersion(bucket, node.path)
            const { stream } = await objects.stream(version, { start: 0, end: Math.min(Number(version.size || 0), size) - 1 })
            const chunks = []
            let total = 0
            for await (const chunk of stream) {
                chunks.push(chunk)
                total += chunk.length
                if (total >= size) break
            }

            return Buffer.concat(chunks).subarray(0, size)
        } catch (err) {
            logger.debug?.({ err, path: node.path }, 'could not sample object for tagging')

            return null
        }
    }

    /** Evaluate the configured rules against an object. */
    const rulesFor = async (bucket, node) => {
        const rules = await repo.find('auto_tag_rule', { enabled: true }, { orderBy: [{ column: 'priority', dir: 'asc' }] })

        return rules.filter((rule) => !rule.bucketId || rule.bucketId === bucket.id)
            .filter((rule) => !rule.prefix || String(node.path).startsWith(rule.prefix))
    }

    const matchesConditions = (rule, ctx) => {
        const conditions = rule.conditions || {}
        const { tags } = ctx
        if (conditions.extensions && conditions.extensions.length) {
            const ext = `.${String(ctx.name).split('.').pop().toLowerCase()}`
            if (!conditions.extensions.map((e) => (e.startsWith('.') ? e : `.${e}`)).includes(ext)) return false
        }
        if (conditions.contentTypes && conditions.contentTypes.length) {
            if (!conditions.contentTypes.some((c) => String(ctx.contentType || '').includes(c))) return false
        }
        if (conditions.pathRegex && !new RegExp(conditions.pathRegex).test(ctx.path)) return false
        if (conditions.tagEquals) {
            const ok = Object.entries(conditions.tagEquals).every(([k, v]) => tags[k] === v)
            if (!ok) return false
        }
        if (conditions.tagIn) {
            const ok = Object.entries(conditions.tagIn).some(([k, values]) => [].concat(values).includes(tags[k]))
            if (!ok) return false
        }
        if (conditions.minSize !== undefined && Number(ctx.size) < Number(conditions.minSize)) return false
        if (conditions.maxSize !== undefined && Number(ctx.size) > Number(conditions.maxSize)) return false
        if (conditions.minConfidence !== undefined && Number(ctx.confidence) < Number(conditions.minConfidence)) return false
        if (conditions.contentRegex && !new RegExp(conditions.contentRegex).test(ctx.text || '')) return false

        return true
    }

    /**
     * Classify an object and merge the resulting tags into the object row and
     * the tag index. Called on upload (applyOn upload/both) and by `sweep()`.
     */
    const applyOnUpload = async ({ bucket, node, actor }) => {
        if (!node || node.type !== 'file') return { tags: {}, applied: [] }
        const rules = await rulesFor(bucket, node)
        const active = rules.filter((rule) => rule.applyOn === 'upload' || rule.applyOn === 'both')
        const sample = await readSample(bucket, node)
        const base = classify({
            name: node.name, contentType: node.contentType, size: node.size, sample,
        })
        const ai = await classifyWithAi({
            name: node.name, contentType: node.contentType, size: node.size, sample,
        })
        const classification = ai && ai.confidence >= aiMinConfidence
            ? { tags: { ...ai.tags }, confidence: ai.confidence, engine: ai.engine }
            : base
        // the sensitive-data scan always runs, even when the AI tagged the object
        const safety = classify({ name: node.name, contentType: node.contentType, size: node.size, sample })
        const merged = { ...classification.tags }
        if (safety.tags.sensitive) {
            merged.sensitive = 'true'
            if (safety.tags.pii) merged.pii = safety.tags.pii
            if (safety.tags.secrets) merged.secrets = safety.tags.secrets
        }

        const ctx = {
            name: node.name,
            path: node.path,
            contentType: node.contentType,
            size: node.size,
            tags: merged,
            confidence: classification.confidence,
            text: sample ? sample.toString('utf8') : '',
        }
        const result = { engine: classification.engine, confidence: classification.confidence }
        let finalTags = null
        for (const rule of active) {
            if (!matchesConditions(rule, ctx)) continue
            const ruleTags = rule.tags || {}
            finalTags = rule.mode === 'replace' ? { ...ruleTags } : { ...(finalTags || merged), ...ruleTags }
            result[`rule:${rule.name}`] = Object.keys(ruleTags)
            // eslint-disable-next-line no-await-in-loop
            await repo.update('auto_tag_rule', { id: rule.id }, { lastRunAt: new Date() })
        }
        if (!finalTags) finalTags = merged

        // auto-tagging never overwrites a user supplied tag with the same key
        const existing = node.tags || {}
        const userTags = Object.fromEntries(Object.entries(existing).filter(([k]) => !k.startsWith('ai:')))
        const tags = {}
        Object.entries(finalTags).forEach(([k, v]) => {
            if (userTags[k] === undefined) tags[`ai:${k}`] = String(v)
        })
        const combined = { ...userTags, ...tags }
        if (Object.keys(tags).length) {
            await repo.update('directory', { id: node.id }, { tags: combined })
            if (node.latestVersionId) {
                await repo.update('object_version', { id: node.latestVersionId }, { tags: combined })
            }
            await indexTags(node.id, bucket.id, combined)
            await audit?.record({
                action: 'tagging.applied',
                actor: 'system',
                actorType: 'system',
                resource: `arn:ddrive:s3:::${bucket.name}/${node.path}`,
                bucket: bucket.name,
                bucketId: bucket.id,
                objectKey: node.path,
                detail: { engine: classification.confidence, tags },
                protocol: 'internal',
            })
            await deps.events?.emit('OBJECT_TAGGING', {
                bucket, node, actor: actor || { name: 'system' }, tags,
            })
        }
        result.tags = tags

        return result
    }

    /** Mirror tags into the searchable tag index. */
    const indexTags = async (objectId, bucketId, tags = {}) => {
        await repo.delete('object_tag', { objectId })
        const rows = Object.entries(tags).map(([key, value]) => ({
            objectId,
            bucketId,
            key,
            value: String(value),
            source: key.startsWith('ai:') ? 'ai' : 'user',
        }))
        if (rows.length) await repo.insertMany('object_tag', rows)

        return rows.length
    }

    const removeObjectTags = (objectId) => repo.delete('object_tag', { objectId })

    /** Tag based object search (used by the console and the REST API). */
    const searchByTag = async ({ bucketId, key, value, limit = 100 }) => {
        const where = {}
        if (bucketId) where.bucketId = bucketId
        if (key) where.key = key
        if (value) where.value = value
        const rows = await repo.find('object_tag', where, { limit })
        if (!rows.length) return []

        return repo.find('directory', { id: { in: [...new Set(rows.map((r) => r.objectId))] }, deletedAt: null })
    }

    /** Re-run rules over existing objects (applyOn sweep/both). */
    const sweep = async ({ bucket, limit = 500 } = {}) => {
        const rules = await repo.find('auto_tag_rule', { enabled: true })
        const sweepRules = rules.filter((rule) => rule.applyOn === 'sweep' || rule.applyOn === 'both')
        if (!sweepRules.length) return { scanned: 0, tagged: 0 }
        const where = { type: 'file', deletedAt: null }
        if (bucket) where.bucketId = bucket.id
        const nodes = await repo.find('directory', where, { limit })
        let tagged = 0
        for (const node of nodes) {
            // eslint-disable-next-line no-await-in-loop
            const bucketRow = bucket || await repo.findOne('bucket', { id: node.bucketId })
            // eslint-disable-next-line no-await-in-loop
            const res = await applyOnUpload({ bucket: bucketRow, node }).catch(() => null)
            if (res && Object.keys(res.tags || {}).length) tagged += 1
        }

        return { scanned: nodes.length, tagged }
    }

    const listRules = () => repo.find('auto_tag_rule', {}, { orderBy: [{ column: 'priority', dir: 'asc' }] })
    const createRule = async (input) => {
        if (!input.name) throw errors.validation('Rule name is required')

        return repo.insert('auto_tag_rule', {
            name: input.name,
            enabled: input.enabled !== false,
            bucketId: input.bucketId || null,
            prefix: input.prefix || null,
            priority: input.priority ?? 10,
            conditions: input.conditions || {},
            tags: input.tags || {},
            mode: input.mode || 'merge',
            applyOn: input.applyOn || 'upload',
        })
    }
    const updateRule = (id, patch) => repo.update('auto_tag_rule', { id }, patch)
    const deleteRule = (id) => repo.delete('auto_tag_rule', { id })

    return {
        classify,
        classifyWithAi,
        applyOnUpload,
        readSample,
        indexTags,
        removeObjectTags,
        searchByTag,
        sweep,
        listRules,
        createRule,
        updateRule,
        deleteRule,
        enabled,
        enabledAi: enabled,
        listRulesRaw: listRules,
        MAX_SAMPLE,
    }
}

module.exports = { createTagger, classify, MAX_SAMPLE }
