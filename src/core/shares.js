/**
 * Share links: capability URLs for objects with optional password, expiry and
 * download limits. Share tokens are unguessable (192 bits) and every access is
 * audited with the link id so a token can be revoked at any time.
 */
const util = require('../lib/util')
const { errors } = require('../lib/errors')

const createShares = (deps = {}) => {
    const { repo, objects, crypto, audit } = deps

    const create = async (bucket, path, opts = {}) => {
        const node = await objects.getNode(bucket.id, util.normalizeKey(path))
        if (!node || node.deletedAt) throw errors.noSuchKey(path)
        const token = util.randomToken(24)
        let passwordHash = null
        let passwordSalt = null
        if (opts.password) {
            const hashed = crypto.hashPassword(opts.password)
            passwordHash = hashed.hash
            passwordSalt = hashed.salt
        }
        const share = await repo.insert('share_link', {
            objectId: node.id,
            bucketId: bucket.id,
            token,
            path: node.path,
            permission: opts.permission || 'read',
            passwordHash,
            passwordSalt,
            expiresAt: opts.expiresInSeconds ? new Date(Date.now() + opts.expiresInSeconds * 1000) : (opts.expiresAt ? new Date(opts.expiresAt) : null),
            maxDownloads: opts.maxDownloads || null,
            createdBy: opts.actor?.name || null,
        })
        await audit?.record({
            action: 'share.create',
            actor: opts.actor?.name, actorId: opts.actor?.id, actorType: 'user',
            resource: `share:${token.slice(0, 6)}…`, bucket: bucket.name, objectKey: node.path, protocol: opts.actor?.protocol,
        })

        return { ...share, url: `/share/${token}` }
    }

    const resolve = async (token, { password } = {}) => {
        const share = await repo.findOne('share_link', { token })
        // unknown or revoked token: nothing to authorise against, so this is a
        // missing resource - do not confirm whether the token ever existed
        if (!share) throw errors.noSuchShare(token)
        if (share.expiresAt && new Date(share.expiresAt).getTime() < Date.now()) throw errors.accessDenied('Share link has expired')
        if (share.maxDownloads && Number(share.downloads) >= Number(share.maxDownloads)) throw errors.accessDenied('Share link download limit reached')
        if (share.passwordHash) {
            if (!password || !crypto.verifyPassword(password, share.passwordHash, share.passwordSalt)) {
                const err = errors.accessDenied('Share link password required')
                err.statusCode = 401

                throw err
            }
        }

        return share
    }

    const recordDownload = async (share) => {
        await repo.update('share_link', { id: share.id }, {
            downloads: Number(share.downloads || 0) + 1,
            lastAccessAt: new Date(),
        })
    }

    const list = (bucket) => repo.find('share_link', bucket ? { bucketId: bucket.id } : {}, { orderBy: [{ column: 'createdAt', dir: 'desc' }] })

    const revoke = async (token, actor = {}) => {
        const share = await repo.findOne('share_link', { token })
        if (!share) throw errors.noSuchShare(token)
        await repo.delete('share_link', { id: share.id })
        await audit?.record({
            action: 'share.revoke', actor: actor.name, actorId: actor.id, actorType: 'user', resource: `share:${token.slice(0, 6)}…`,
        })

        return true
    }

    return { create, resolve, recordDownload, list, revoke }
}

module.exports = { createShares }
