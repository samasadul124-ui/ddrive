/**
 * Chunked stream writer with bounded parallelism.
 *
 * Reads a Readable, assembles fixed size chunks and hands them to an async
 * processor with at most `concurrency` in-flight operations. Backpressure is
 * preserved: the source stream is paused until a worker slot frees up. All
 * worker failures are collected (never left as unhandled rejections) and
 * re-thrown to the caller so it can clean up the chunks that were written.
 */
const { MAX_CHUNK_SIZE: SHARED_MAX_CHUNK_SIZE } = require('../lib/limits')

const MAX_CHUNK_SIZE = SHARED_MAX_CHUNK_SIZE

/**
 * @param {import('stream').Readable} stream
 * @param {object} opts
 * @param {number} opts.chunkSize
 * @param {number} [opts.concurrency=3]
 * @param {(buffer: Buffer, index: number) => Promise<any>} opts.onChunk
 * @returns {Promise<{ chunks: any[], size: number, count: number }>}
 */
const writeChunksFromStream = async (stream, opts) => {
    const chunkSize = Math.min(opts.chunkSize || MAX_CHUNK_SIZE, MAX_CHUNK_SIZE)
    const concurrency = Math.max(1, opts.concurrency || 3)
    const { onChunk } = opts

    const results = []
    const failures = []
    const pending = new Set()
    let pendingBuffer = []
    let pendingLength = 0
    let size = 0
    let index = 0

    const dispatch = (buffer, idx) => {
        const task = Promise.resolve()
            .then(() => onChunk(buffer, idx))
            .then((res) => { results[idx] = res; })
            .catch((err) => { failures.push(err); })
            .then(() => { pending.delete(task); })
        pending.add(task)
    }

    const waitForSlot = async () => {
        if (pending.size < concurrency) return
        await Promise.race(pending)
    }

    // eslint-disable-next-line no-restricted-syntax
    for await (const data of stream) {
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data)
        pendingBuffer.push(buffer)
        pendingLength += buffer.length
        size += buffer.length
        while (pendingLength >= chunkSize) {
            const joined = Buffer.concat(pendingBuffer, pendingLength)
            const chunk = joined.subarray(0, chunkSize)
            const residue = joined.subarray(chunkSize)
            pendingBuffer = residue.length ? [Buffer.from(residue)] : []
            pendingLength = residue.length
            // eslint-disable-next-line no-await-in-loop
            await waitForSlot()
            if (failures.length) break
            dispatch(Buffer.from(chunk), index)
            index += 1
        }
        if (failures.length) break
    }

    if (!failures.length && pendingLength > 0) {
        const chunk = Buffer.concat(pendingBuffer, pendingLength)
        await waitForSlot()
        if (!failures.length) {
            dispatch(chunk, index)
            index += 1
        }
    }

    await Promise.all([...pending])
    if (failures.length) throw failures[0]

    return { chunks: results, size, count: index, concurrency }
}

module.exports = { writeChunksFromStream, MAX_CHUNK_SIZE }
