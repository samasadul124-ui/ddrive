/**
 * In-memory chunk store: used by the test-suite and by ephemeral demo
 * deployments (`STORAGE_DRIVER=memory`).
 */
const crypto = require('crypto')

const createMemoryStore = (opts = {}) => {
    const blobs = new Map()
    const { Readable } = require('stream')

    return {
        name: 'memory',
        tier: opts.tier || 'HOT',
        blobs,
        async init() { return true },
        async put(buffer) {
            const id = crypto.randomUUID()
            blobs.set(id, Buffer.from(buffer))

            return { locator: `mem://${id}`, size: buffer.length, backend: 'memory', tier: this.tier }
        },
        async get(locator, range = {}) {
            const id = String(locator).replace('mem://', '')
            const data = blobs.get(id)
            if (!data) throw new Error(`memory chunk ${id} not found`)
            const slice = range.start === undefined && range.end === undefined
                ? data
                : data.subarray(range.start ?? 0, (range.end ?? data.length - 1) + 1)

            return Readable.from([slice])
        },
        async stat(locator) {
            const data = blobs.get(String(locator).replace('mem://', ''))

            return { size: data ? data.length : 0 }
        },
        async delete(locator) {
            blobs.delete(String(locator).replace('mem://', ''))
        },
        async health() {
            return { ok: true, backend: 'memory', chunks: blobs.size }
        },
    }
}

module.exports = { createMemoryStore }
