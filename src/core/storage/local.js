/**
 * Local filesystem chunk store.
 *
 * Chunks are content-addressable-ish blobs stored in a two-level fanout
 * directory. Locators are relative paths so the data directory can be moved or
 * mounted from any volume (EBS, EFS, NFS, local NVMe).
 */
const fs = require('fs')
const fsp = require('fs/promises')
const path = require('path')
const crypto = require('crypto')
const { randomUUID } = require('crypto')
const { errors } = require('../../lib/errors')

const createLocalStore = (opts = {}) => {
    const root = path.resolve(opts.directory || path.join(process.cwd(), 'data', 'chunks'))

    const resolve = (locator) => {
        const clean = String(locator).replace(/^local:\/\//, '')
        if (clean.includes('..')) throw errors.invalidArgument('Invalid chunk locator')
        const target = path.join(root, clean)
        if (!target.startsWith(root)) throw errors.invalidArgument('Invalid chunk locator')

        return target
    }

    return {
        name: 'local',
        root,
        tier: opts.tier || 'HOT',
        async init() {
            await fsp.mkdir(root, { recursive: true })
        },
        async put(buffer, meta = {}) {
            const id = `${crypto.createHash('sha1').update(buffer).digest('hex').slice(0, 2)}/${randomUUID()}`
            const target = resolve(id)
            await fsp.mkdir(path.dirname(target), { recursive: true })
            await fsp.writeFile(target, buffer)

            return { locator: `local://${id}`, size: buffer.length, backend: 'local', tier: this.tier, meta }
        },
        async get(locator, range = {}) {
            const target = resolve(locator)
            if (range.start === undefined && range.end === undefined) {
                return fs.createReadStream(target)
            }
            let { start, end } = range
            if (start === undefined) {
                const stat = await fsp.stat(target)
                start = Math.max(0, stat.size - end)
                end = stat.size - 1
            }

            return fs.createReadStream(target, { start, end })
        },
        async stat(locator) {
            const stat = await fsp.stat(resolve(locator))

            return { size: stat.size, mtime: stat.mtime }
        },
        async delete(locator) {
            try {
                await fsp.unlink(resolve(locator))
            } catch (err) {
                if (err.code !== 'ENOENT') throw err
            }
        },
        async health() {
            try {
                await fsp.mkdir(root, { recursive: true })
                await fsp.access(root, fs.constants.W_OK)

                return { ok: true, backend: 'local', root }
            } catch (err) {
                return { ok: false, backend: 'local', root, error: err.message }
            }
        },
    }
}

module.exports = { createLocalStore }
