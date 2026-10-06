/**
 * Cryptography for DDrive.
 *
 * Encryption model (envelope encryption, per object, per chunk):
 *
 *   KMS / HSM / env master key   ->  KEK   (never leaves the trust boundary)
 *   random data key per object   ->  DEK   (wrapped with the KEK, stored in `block.wrappedDek`)
 *   DEK + random IV per chunk    ->  ciphertext
 *
 * Supported ciphers: aes-256-ctr (legacy compatible) and aes-256-gcm (default
 * for new installs). Both are decryptable simultaneously; the algorithm is
 * recorded per chunk.
 */
const crypto = require('crypto')
const fs = require('fs')
const { errors } = require('../lib/errors')

const CHUNK_ALGOS = {
    'aes-256-ctr': { ivLength: 16, mode: 'ctr' },
    'aes-256-gcm': { ivLength: 12, mode: 'gcm' },
}

const SCRYPT = {
    N: 16384, r: 8, p: 1, keylen: 64,
}

const deriveKek = (secret) => {
    if (!secret) return null
    const trimmed = String(secret).trim()
    // 32 byte base64 or 64 char hex keys are used verbatim
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, 'hex')
    const decoded = Buffer.from(trimmed, 'base64')
    if (decoded.length === 32 && /^[A-Za-z0-9+/=]+$/.test(trimmed)) return decoded
    // otherwise treat it as a passphrase
    return crypto.scryptSync(trimmed, 'ddrive:kek:v1', 32, { N: 16384, r: 8, p: 1 })
}

/** Local (env/file) key provider - the default and the BYOK "bring your own key" path. */
const createLocalProvider = (opts) => {
    let material = opts.masterKey
    if (!material && opts.masterKeyFile && fs.existsSync(opts.masterKeyFile)) {
        material = fs.readFileSync(opts.masterKeyFile, 'utf8').trim()
    }
    if (!material) return null
    const kek = deriveKek(material)

    return {
        type: 'local',
        keyId: opts.keyId || `local:${crypto.createHash('sha256').update(kek).digest('hex').slice(0, 12)}`,
        async getKek() { return kek },
    }
}

/**
 * External KMS / HSM provider.
 *
 * The provider speaks a tiny JSON protocol so it can be backed by AWS KMS, GCP
 * KMS, Azure Key Vault, Vault Transit, an HSM (PKCS#11 via a KMIP/HTTP bridge)
 * or a Nitrokey/YubiHSM agent:
 *
 *   POST {endpoint}/wrap   { keyId, plaintext: base64 }  -> { wrapped: base64, keyId }
 *   POST {endpoint}/unwrap { keyId, wrapped: base64 }    -> { plaintext: base64 }
 *
 * `DDRIVE_KMS_PROVIDER=hsm` is an alias documented in docs/security.md; the
 * HSM is reached through the same bridge.
 */
const createKmsProvider = (opts) => {
    const { endpoint, token, keyId = 'ddrive-master' } = opts
    if (!endpoint) return null
    const call = async (action, body) => {
        const res = await fetch(`${endpoint.replace(/\/$/, '')}/${action}`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                ...(token ? { authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({ keyId, ...body }),
        })
        if (!res.ok) throw errors.internal(`KMS ${action} failed with status ${res.status}`)
        const json = await res.json()
        if (json.error) throw errors.internal(`KMS ${action} failed: ${json.error}`)

        return json
    }

    return {
        type: opts.providerType || 'kms',
        keyId: opts.keyId || 'kms:default',
        async getKek() { return null },
        async wrap(dek) {
            const { wrapped } = await call('wrap', { plaintext: dek.toString('base64') })

            return Buffer.from(wrapped, 'base64')
        },
        async unwrap(wrapped) {
            const { plaintext } = await call('unwrap', { wrapped: Buffer.from(wrapped).toString('base64') })

            return Buffer.from(plaintext, 'base64')
        },
        async encrypt(plaintext) {
            const { wrapped, keyId: usedKey } = await call('encrypt', { plaintext: plaintext.toString('base64') })

            return { payload: Buffer.from(wrapped, 'base64'), keyId: usedKey || keyId }
        },
        async decrypt(payload, usedKey) {
            const { plaintext } = await call('decrypt', {
                wrapped: Buffer.from(payload).toString('base64'),
                keyId: usedKey,
            })

            return Buffer.from(plaintext, 'base64')
        },
    }
}

const createKeyProvider = (opts = {}) => {
    const provider = createKmsProvider({
        endpoint: opts.kmsEndpoint,
        token: opts.kmsToken,
        keyId: opts.kmsKeyId,
        providerType: opts.kmsProvider,
    }) || createLocalProvider({ masterKey: opts.masterKey, masterKeyFile: opts.masterKeyFile, keyId: opts.keyId })

    return provider
}

class CryptoBox {
    /**
     * @param {object} opts
     * @param {object} [opts.provider] key provider (local/kms/hsm)
     * @param {string} [opts.algorithm='aes-256-gcm']
     * @param {string} [opts.legacySecret] SECRET from DDrive 4.x installs
     */
    constructor(opts = {}) {
        this.provider = opts.provider || null
        this.algorithm = opts.algorithm && CHUNK_ALGOS[opts.algorithm] ? opts.algorithm : 'aes-256-gcm'
        this.legacySecret = opts.legacySecret || null
        this.legacyKey = opts.legacySecret ? crypto.createHash('sha256').update(String(opts.legacySecret)).digest() : null
        this.kekCache = null
    }

    get enabled() {
        return !!(this.provider || this.legacyKey)
    }

    get keyId() {
        return (this.provider && this.provider.keyId) || 'none'
    }

    async getKek() {
        if (!this.provider) throw errors.internal('No encryption key provider configured')
        if (!this.kekCache) this.kekCache = await this.provider.getKek()
        if (!this.kekCache) throw errors.internal('Key provider returned no key material')

        return this.kekCache
    }

    /** Generate a random data encryption key for an object. */
    generateDek() {
        return crypto.randomBytes(32)
    }

    /** Wrap (encrypt) a DEK with the KEK, or delegate to the KMS. */
    async wrapDek(dek) {
        if (this.provider && this.provider.type !== 'local') {
            const wrapped = await this.provider.wrap(dek)

            return { wrappedDek: wrapped.toString('base64'), keyId: this.provider.keyId }
        }
        const kek = await this.getKek()
        const iv = crypto.randomBytes(12)
        const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv)
        const encrypted = Buffer.concat([cipher.update(dek), cipher.final()])
        const tag = cipher.getAuthTag()

        return {
            wrappedDek: `v1:${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`,
            keyId: this.provider.keyId,
        }
    }

    async unwrapDek(wrappedDek) {
        if (this.provider && this.provider.type !== 'local') {
            return this.provider.unwrap(Buffer.from(wrappedDek, 'base64'))
        }
        const kek = await this.getKek()
        const [version, ivB64, tagB64, dataB64] = String(wrappedDek).split(':')
        if (version !== 'v1' || !ivB64 || !tagB64 || !dataB64) throw errors.internal('Malformed wrapped data key')
        const decipher = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(ivB64, 'base64'))
        decipher.setAuthTag(Buffer.from(tagB64, 'base64'))

        return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()])
    }

    /**
     * Encrypt one chunk with the object DEK.
     * @returns {{ data: Buffer, iv: string }}
     */
    encryptChunk(dek, plaintext, algorithm = this.algorithm) {
        const spec = CHUNK_ALGOS[algorithm] || CHUNK_ALGOS['aes-256-gcm']
        const iv = crypto.randomBytes(spec.ivLength)
        const cipher = crypto.createCipheriv(algorithm, dek, iv)
        const data = Buffer.concat([cipher.update(plaintext), cipher.final()])
        if (spec.mode === 'gcm') {
            const tag = cipher.getAuthTag()

            return { data, iv: `${iv.toString('base64')}:${tag.toString('base64')}`, algorithm }
        }

        return { data, iv: iv.toString('hex'), algorithm }
    }

    /** Create a decipher transform for one chunk. */
    chunkDecipher({ iv, wrappedDek, dek, encAlg }, legacyKey) {
        if (wrappedDek) {
            return this.unwrapAndDecipher({ iv, wrappedDek, encAlg })
        }
        const algorithm = encAlg || 'aes-256-ctr'
        const spec = CHUNK_ALGOS[algorithm]
        if (!spec) throw errors.internal(`Unsupported encryption algorithm ${algorithm}`)
        const key = dek || legacyKey
        if (!key) throw errors.internal('Missing key material for encrypted chunk')
        if (spec.mode === 'gcm') {
            const [ivB64, tagB64] = String(iv).split(':')
            const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivB64, 'base64'))
            decipher.setAuthTag(Buffer.from(tagB64, 'base64'))

            return decipher
        }
        const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(String(iv), 'hex'))

        return decipher
    }

    async unwrapAndDecipher({ iv, wrappedDek, encAlg }) {
        const algorithm = encAlg || this.algorithm
        const spec = CHUNK_ALGOS[algorithm]
        if (!spec) throw errors.internal(`Unsupported encryption algorithm ${algorithm}`)
        const dek = await this.unwrapDek(wrappedDek)
        if (spec.mode === 'gcm') {
            const [ivB64, tagB64] = String(iv).split(':')
            const decipher = crypto.createDecipheriv(algorithm, dek, Buffer.from(ivB64, 'base64'))
            decipher.setAuthTag(Buffer.from(tagB64, 'base64'))

            return decipher
        }

        return crypto.createDecipheriv(algorithm, dek, Buffer.from(String(iv), 'hex'))
    }

    /** Legacy DDrive 4.x chunks: key = sha256(SECRET), aes-256-ctr, hex IV. */
    legacyDecipher(iv) {
        if (!this.legacyKey) throw errors.internal('Encrypted object requires SECRET (legacy secret) to be configured')

        return crypto.createDecipheriv('aes-256-ctr', this.legacyKey, Buffer.from(String(iv), 'hex'))
    }

    // ------------------------------------------------------------------
    // Password hashing & small secret encryption (access keys, peer creds)
    // ------------------------------------------------------------------
    hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
        const hash = crypto.scryptSync(String(password), salt, SCRYPT.keylen, {
            N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p,
        }).toString('hex')

        return { hash, salt }
    }

    verifyPassword(password, hash, salt) {
        if (!hash || !salt) return false
        const candidate = crypto.scryptSync(String(password), salt, SCRYPT.keylen, {
            N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p,
        }).toString('hex')
        const a = Buffer.from(candidate, 'hex')
        const b = Buffer.from(hash, 'hex')

        return a.length === b.length && crypto.timingSafeEqual(a, b)
    }

    /** Encrypt a small secret (<= 1KiB) with the KEK. */
    async encryptSecret(plaintext, keyId) {
        const kek = await this.getKek()
        const iv = crypto.randomBytes(12)
        const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv)
        const enc = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()])

        return { value: enc.toString('base64'), iv: iv.toString('base64'), authTag: cipher.getAuthTag().toString('base64'), keyId: keyId || this.keyId }
    }

    async decryptSecret({ value, iv, authTag }) {
        const kek = await this.getKek()
        const decipher = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(iv, 'base64'))
        decipher.setAuthTag(Buffer.from(authTag, 'base64'))

        return Buffer.concat([decipher.update(Buffer.from(value, 'base64')), decipher.final()]).toString()
    }

    // ------------------------------------------------------------------
    // Console session tokens (HMAC signed, no external dependency)
    // ------------------------------------------------------------------
    signToken(payload, expiresInSeconds = 3600 * 12, secretKey) {
        const body = { ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds }
        const encoded = Buffer.from(JSON.stringify(body)).toString('base64url')
        const key = secretKey || this.sessionSecret
        const sig = crypto.createHmac('sha256', key).update(encoded).digest('base64url')

        return `${encoded}.${sig}`
    }

    verifyToken(token, secretKey) {
        if (!token || typeof token !== 'string') return null
        const [encoded, sig] = token.split('.')
        if (!encoded || !sig) return null
        const key = secretKey || this.sessionSecret
        const expected = crypto.createHmac('sha256', key).update(encoded).digest('base64url')
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null
        try {
            const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString())
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null

            return payload
        } catch {
            return null
        }
    }

    get sessionSecret() {
        if (this._sessionSecret) return this._sessionSecret
        if (this.provider && this.provider.type === 'local') {
            // deterministic from the master key so restarts keep sessions valid
            this._sessionSecret = crypto.createHash('sha256').update(`session:${this.provider.keyId}`).digest()
        } else if (process.env.SESSION_SECRET) {
            this._sessionSecret = crypto.createHash('sha256').update(process.env.SESSION_SECRET).digest()
        } else {
            this._sessionSecret = crypto.randomBytes(32)
        }

        return this._sessionSecret
    }
}

module.exports = { CryptoBox, createKeyProvider, deriveKek, CHUNK_ALGOS }
