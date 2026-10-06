/**
 * TOTP (RFC 6238) — used for console two-factor authentication.
 */
const crypto = require('crypto')
const util = require('./util')

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

const base32Encode = (buffer) => {
    let bits = 0
    let value = 0
    let output = ''
    for (const byte of buffer) {
        value = (value << 8) | byte
        bits += 8
        while (bits >= 5) {
            output += BASE32[(value >>> (bits - 5)) & 31]
            bits -= 5
        }
    }
    if (bits > 0) output += BASE32[(value << (5 - bits)) & 31]

    return output
}

const base32Decode = (input) => {
    const clean = String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '')
    let bits = 0
    let value = 0
    const bytes = []
    for (const char of clean) {
        const index = BASE32.indexOf(char)
        if (index < 0) continue
        value = (value << 5) | index
        bits += 5
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 0xff)
            bits -= 8
        }
    }

    return Buffer.from(bytes)
}

const generateSecret = (length = 20) => base32Encode(crypto.randomBytes(length))

const hotp = (secret, counter, digits = 6, algorithm = 'sha1') => {
    const buffer = Buffer.alloc(8)
    buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0)
    buffer.writeUInt32BE(counter % 2 ** 32, 4)
    const digest = crypto.createHmac(algorithm, base32Decode(secret)).update(buffer).digest()
    const offset = digest[digest.length - 1] & 0x0f
    const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff)

    return String(binary % (10 ** digits)).padStart(digits, '0')
}

const totp = (secret, { time = Date.now(), step = 30, digits = 6, algorithm = 'sha1' } = {}) => hotp(secret, Math.floor(time / 1000 / step), digits, algorithm)

/** Verify with +/- 1 step tolerance. */
const verifyTotp = (secret, token, opts = {}) => {
    if (!secret || !token) return false
    const clean = String(token).replace(/\s+/g, '')
    const time = opts.time || Date.now()
    for (const offset of [-1, 0, 1]) {
        const expected = totp(secret, { ...opts, time: time + offset * (opts.step || 30) * 1000 })
        if (expected.length === clean.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) return true
    }

    return false
}

const provisioningUri = ({ secret, account, issuer = 'DDrive', digits = 6, step = 30 }) => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${digits}&period=${step}`

void util

module.exports = {
    generateSecret, totp, hotp, verifyTotp, provisioningUri, base32Encode, base32Decode,
}
