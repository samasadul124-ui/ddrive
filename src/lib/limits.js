/**
 * Chunk size limits, in one place.
 *
 * DDrive splits an object into fixed-size chunks and stores each chunk as one
 * blob. The maximum size of that blob is a property of the *backend*, and the
 * backends disagree:
 *
 *   discord  a webhook attachment is capped at 10 MiB (Discord's upload limit
 *            for a normal channel). Anything larger is rejected with HTTP 413,
 *            which is why the default chunk size must never exceed it - a
 *            24 MiB default made every upload to Discord fail.
 *   local    no meaningful limit; the ceiling below is a memory/throughput
 *   s3       trade-off, not a backend restriction.
 *   memory   testing only.
 *
 * `DEFAULT_CHUNK_SIZE` is therefore the Discord limit: it is the only value
 * that is safe for every backend, and changing the default must not silently
 * break Discord deployments.
 *
 * Note that these are *limits*, not tunables: an existing object keeps the
 * chunk size it was written with, and the download path reads the per-version
 * chunk size from the stored blocks (see src/http/api/routes/file/download.js),
 * so raising or lowering CHUNK_SIZE never invalidates stored data.
 */
const MiB = 1024 * 1024

/** Largest request a Discord webhook accepts (10 MiB). */
const DISCORD_ATTACHMENT_LIMIT = 10 * MiB // 10485760

/**
 * Headroom for everything that is written *around* the chunk bytes:
 *   - the multipart envelope (boundary, `Content-Disposition`, filename)
 *   - the per-chunk AES-GCM overhead when encryption is enabled (iv, auth tag)
 * Discord applies its limit to the whole request, so a chunk of exactly 10 MiB
 * produces a body slightly larger than 10 MiB and is rejected with HTTP 413.
 * 64 KiB of slack removes that class of failure entirely; it costs one extra
 * chunk per ~160 GB of data.
 */
const DISCORD_ENVELOPE_ALLOWANCE = 64 * 1024

/** Largest chunk that can safely be sent to Discord. */
const DISCORD_MAX_CHUNK = DISCORD_ATTACHMENT_LIMIT - DISCORD_ENVELOPE_ALLOWANCE // 10420224

/** Ceiling for backends without a hard limit (historically "just under 25 MiB"). */
const MAX_CHUNK_SIZE = 26109542

/** Default chunk size: safe for every backend, including Discord. */
const DEFAULT_CHUNK_SIZE = DISCORD_MAX_CHUNK

/** Human readable byte count for log lines and error messages. */
const humanBytes = (bytes) => {
    const value = Number(bytes) || 0
    if (value >= MiB) return `${(value / MiB).toFixed(value % MiB === 0 ? 0 : 1)} MiB`
    if (value >= 1024) return `${(value / 1024).toFixed(0)} KiB`

    return `${value} B`
}

module.exports = {
    MiB,
    DISCORD_ATTACHMENT_LIMIT,
    DISCORD_ENVELOPE_ALLOWANCE,
    DISCORD_MAX_CHUNK,
    MAX_CHUNK_SIZE,
    DEFAULT_CHUNK_SIZE,
    humanBytes,
}
