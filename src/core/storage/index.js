/**
 * Chunk storage facade.
 *
 * A chunk is an opaque blob (up to `maxChunkSize`; see src/lib/limits.js) that the
 * object service encrypts and stores through this facade. The facade routes
 * each operation to the right backend based on the locator scheme, which makes
 * tiering transparent for the rest of the system:
 *
 *   local://<tier>/<path>   local filesystem tier
 *   mem://<id>              in-memory (tests)
 *   s3://<bucket>/<key>     remote S3-compatible tier
 *   https://cdn.discordapp.com/...   Discord attachments
 *
 * Tiers: HOT (default), COOL, ARCHIVE. `move()` performs a tiering transition
 * by copying the blob to the target tier and deleting the source copy.
 */
const { errors } = require('../../lib/errors')
const { createLocalStore } = require('./local')
const { createMemoryStore } = require('./memory')
const { createDiscordStore, MAX_ATTACHMENT } = require('./discord')
const { DEFAULT_CHUNK_SIZE } = require('../../lib/limits')
const { createS3Store } = require('./s3')
const { streamToBuffer } = require('../../lib/util')

const TIERS = ['HOT', 'COOL', 'ARCHIVE']

const parseLocator = (locator) => {
    const value = String(locator)
    const match = /^([a-z0-9+]+):\/\/([^/]*)\/?(.*)$/i.exec(value)
    if (!match) return { scheme: 'https', tier: null, id: value }

    return { scheme: match[1].toLowerCase(), tier: match[2] || null, id: match[3] }
}

/**
 * @param {object} config
 * @param {'local'|'discord'|'memory'} config.driver
 * @param {object} config.local        { directory }
 * @param {object} config.discord      { webhooks, timeout, concurrency }
 * @param {object} config.cool         optional { driver, local|s3 config }
 * @param {object} config.archive      optional { driver, local|s3 config }
 */
const createChunkStore = (config = {}) => {
    const driver = config.driver || 'local'
    const makeStore = (spec, tier) => {
        if (!spec) return null
        const specDriver = spec.driver || driver
        if (specDriver === 'local') {
            return createLocalStore({ directory: spec.directory, tier })
        }
        if (specDriver === 'memory') return createMemoryStore({ tier })
        if (specDriver === 's3') return createS3Store({ ...spec, tier })
        if (specDriver === 'discord') return createDiscordStore({ ...spec, tier, ...config.discord })
        throw errors.invalidArgument(`Unknown storage driver "${specDriver}"`)
    }

    const primary = driver === 'discord'
        ? createDiscordStore({ ...config.discord, tier: 'HOT' })
        : driver === 'memory'
            ? createMemoryStore({ tier: 'HOT' })
            : createLocalStore({ ...config.local, tier: 'HOT' })

    const stores = { HOT: primary }
    const cool = makeStore(config.cool, 'COOL')
    const archive = makeStore(config.archive, 'ARCHIVE')
    if (cool) stores.COOL = cool
    if (archive) stores.ARCHIVE = archive

    const resolveStore = (locator) => {
        const { scheme, tier } = parseLocator(locator)
        if (scheme === 'mem') return stores.HOT
        if (scheme === 's3') return stores.ARCHIVE && stores.ARCHIVE.name === 's3' ? stores.ARCHIVE : stores.COOL
        if (scheme === 'local') {
            if (tier && stores[tier] && stores[tier].name === 'local') return stores[tier]

            return stores.HOT
        }

        return stores.HOT // discord CDN or any other https URL
    }

    const tierDefaults = (tier) => {
        const store = stores[tier] || stores.HOT

        return store.tier || 'HOT'
    }

    return {
        driver,
        maxChunkSize: primary.maxChunkSize || config.maxChunkSize || DEFAULT_CHUNK_SIZE,
        concurrency: primary.concurrency || config.concurrency || 3,
        stores,
        tiers: Object.keys(stores),
        async init() {
            await Promise.all(Object.values(stores).filter(Boolean).map((s) => s.init()))
        },
        /**
         * Store a chunk.
         * @param {Buffer} buffer
         * @param {object} [opts] { tier, key }
         */
        async put(buffer, opts = {}) {
            const tier = TIERS.includes(opts.tier) ? opts.tier : 'HOT'
            const store = stores[tier] || stores.HOT
            const storeLimit = store.maxChunkSize || this.maxChunkSize
            if (storeLimit && buffer.length > storeLimit) {
                throw errors.invalidArgument(
                    `chunk of ${buffer.length} bytes exceeds the ${store.name} backend limit of ${storeLimit} bytes; `
                    + `lower CHUNK_SIZE to ${storeLimit} or below`,
                )
            }
            const res = await store.put(buffer, { key: opts.key })

            return { ...res, tier: store.tier || tier }
        },
        /** Read a chunk (optionally a byte range) as a stream. */
        get(locator, range) {
            return resolveStore(locator).get(locator, range)
        },
        async stat(locator) {
            const store = resolveStore(locator)
            if (!store.stat) throw errors.notImplemented('stat is not supported by this backend')

            return store.stat(locator)
        },
        async delete(locator) {
            await resolveStore(locator).delete(locator)
        },
        /** Move a chunk to another tier, returning the new locator. */
        async move(locator, targetTier) {
            const target = stores[targetTier]
            if (!target) throw errors.invalidArgument(`Tier ${targetTier} is not configured`)
            const source = resolveStore(locator)
            if (source === target) return { locator, tier: targetTier, moved: false }
            const stream = await source.get(locator)
            const buffer = await streamToBuffer(stream)
            const res = await target.put(buffer, { key: locator })
            await source.delete(locator)

            return { ...res, moved: true }
        },
        async health() {
            const entries = await Promise.all(Object.entries(stores).map(async ([tier, store]) => [tier, await store.health()]))

            return Object.fromEntries(entries)
        },
        maxAttachmentSize: MAX_ATTACHMENT,
        parseLocator,
    }
}

module.exports = { createChunkStore, parseLocator, TIERS }
