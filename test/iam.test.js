/**
 * IAM: users, groups, roles and policy documents, access-key lifecycle and the
 * authorization decisions the protocol servers rely on.
 */
const test = require('node:test')
const assert = require('node:assert/strict')

const { createTestServer } = require('./helpers')

const STRONG = 'Str0ngPassw0rd!x'

test('users can be created, listed, updated and deleted', async () => {
    const t = await createTestServer()
    try {
        const created = await t.json('POST', '/api/admin/users', {
            username: 'alice', password: STRONG, displayName: 'Alice A',
        })
        assert.equal(created.statusCode, 201)
        assert.equal(t.body(created).username, 'alice')

        const listed = await t.json('GET', '/api/admin/users')
        const alice = t.body(listed).users.find((u) => u.username === 'alice')
        assert.ok(alice, 'the new user must be listed')
        assert.equal(alice.passwordHash, undefined, 'the API must never expose password hashes')
        assert.equal(alice.secretEnc, undefined, 'nor encrypted secrets')

        const patched = await t.json('PATCH', '/api/admin/users/alice', { displayName: 'Alice B' })
        assert.equal(patched.statusCode, 200)
        assert.equal(t.body(await t.json('GET', '/api/admin/users')).users.find((u) => u.username === 'alice').displayName, 'Alice B')

        // alice can log in with her own credentials
        const login = await t.http.inject({
            method: 'POST',
            url: '/api/login',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ username: 'alice', password: STRONG }),
        })
        assert.equal(login.statusCode, 200)

        const duplicate = await t.json('POST', '/api/admin/users', { username: 'alice', password: STRONG })
        assert.equal(duplicate.statusCode, 409, 'duplicate usernames are a conflict, not a 500')

        const removed = await t.json('DELETE', '/api/admin/users/alice')
        assert.equal(removed.statusCode, 204)
        assert.equal(t.body(await t.json('GET', '/api/admin/users')).users.some((u) => u.username === 'alice'), false)
    } finally {
        await t.close()
    }
})

test('password policy rejects weak passwords and usernames inside passwords', async () => {
    const t = await createTestServer()
    try {
        const weak = await t.json('POST', '/api/admin/users', { username: 'bob', password: 'short' })
        assert.equal(weak.statusCode, 400)

        const containsName = await t.json('POST', '/api/admin/users', { username: 'bob', password: 'bobpass1234' })
        assert.equal(containsName.statusCode, 400)

        const noUser = await t.json('POST', '/api/admin/users', { username: 'bob' })
        assert.equal(noUser.statusCode, 400)

        assert.equal((await t.json('POST', '/api/admin/users', { username: 'bob', password: STRONG })).statusCode, 201)
    } finally {
        await t.close()
    }
})

test('unknown users, groups, roles and access keys report 404 rather than 500', async () => {
    const t = await createTestServer()
    try {
        assert.equal((await t.json('DELETE', '/api/admin/users/ghost')).statusCode, 404)
        assert.equal((await t.json('PATCH', '/api/admin/users/ghost', { displayName: 'x' })).statusCode, 404)
        assert.equal((await t.json('POST', '/api/admin/access-keys', { username: 'ghost' })).statusCode, 404)
        assert.equal((await t.json('PATCH', '/api/admin/users/admin', { roles: ['no-such-role'] })).statusCode, 404)
        assert.equal((await t.json('DELETE', '/api/admin/groups/ghost')).statusCode, 404)
        assert.equal((await t.json('PATCH', '/api/admin/roles/ghost', { description: 'x' })).statusCode, 404)
        assert.equal((await t.json('POST', '/api/admin/groups/ghost/members', { username: 'admin' })).statusCode, 404)
    } finally {
        await t.close()
    }
})

test('access keys authenticate as their owner, verify their secret and can be revoked', async () => {
    const t = await createTestServer()
    try {
        const created = await t.json('POST', '/api/admin/access-keys', { username: 'admin', description: 'test key' })
        assert.equal(created.statusCode, 201)
        const key = t.body(created)
        assert.match(key.accessKeyId, /^DD[0-9A-F]{16}$/)
        assert.ok(key.secretAccessKey.length >= 32)

        const listed = await t.json('GET', '/api/admin/access-keys')
        const row = t.body(listed).keys.find((k) => k.accessKeyId === key.accessKeyId)
        assert.ok(row, 'the key must be listed')
        assert.equal(row.secretAccessKey, undefined, 'secrets are shown once, never in listings')
        assert.equal(row.secretEnc, undefined, 'the stored secret must stay encrypted')

        const resolved = await t.context.iam.resolveAccessKey(key.accessKeyId)
        assert.ok(resolved)
        assert.equal(resolved.secretAccessKey, key.secretAccessKey, 'the stored secret must decrypt back to what was issued')

        // unknown / revoked keys do not resolve
        assert.equal(await t.context.iam.resolveAccessKey('DD0000000000000000'), null)

        const revoked = await t.json('DELETE', `/api/admin/access-keys/${key.accessKeyId}`)
        assert.equal(revoked.statusCode, 204)
        assert.equal(await t.context.iam.resolveAccessKey(key.accessKeyId), null)
    } finally {
        await t.close()
    }
})

test('a role grants exactly the actions in its policy document', async () => {
    const t = await createTestServer()
    try {
        assert.equal((await t.json('POST', '/api/admin/users', { username: 'carol', password: STRONG })).statusCode, 201)

        const role = await t.json('POST', '/api/admin/roles', {
            name: 'reader',
            policies: [{
                Version: '2012-10-17',
                Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: ['*'] }],
            }],
        })
        assert.equal(role.statusCode, 201, role.body)

        // bind the role to carol by name
        const bound = await t.json('PATCH', '/api/admin/users/carol', { roles: ['reader'] })
        assert.equal(bound.statusCode, 200)

        const carol = await t.context.iam.getUser('carol')
        const principal = await t.context.iam.buildPrincipal(carol)
        assert.deepEqual(principal.roles, ['reader'])

        const bucket = { bucket: 'ddrive' }
        assert.equal(await t.context.iam.authorize(principal, 's3:GetObject', { ...bucket, key: 'a.txt' }), true)
        assert.equal(await t.context.iam.authorize(principal, 's3:ListBucket', bucket), true)
        // a denied action throws an AccessDenied error (the servers turn it into a 403)
        await assert.rejects(
            () => t.context.iam.authorize(principal, 's3:DeleteObject', { ...bucket, key: 'a.txt' }),
            { code: 'AccessDenied' },
        )
        await assert.rejects(
            () => t.context.iam.authorize(principal, 's3:PutObject', { ...bucket, key: 'a.txt' }),
            { code: 'AccessDenied' },
        )
    } finally {
        await t.close()
    }
})

test('group membership grants the group roles', async () => {
    const t = await createTestServer()
    try {
        await t.json('POST', '/api/admin/policies', {
            name: 'list-only',
            document: {
                Version: '2012-10-17',
                Statement: [{ Effect: 'Allow', Action: ['s3:ListBucket'], Resource: ['*'] }],
            },
        })
        await t.json('POST', '/api/admin/roles', { name: 'listing', policies: ['list-only'] })
        const group = t.body(await t.json('POST', '/api/admin/groups', { name: 'analysts' }))

        // group gets the role, user gets the group
        assert.equal((await t.json('POST', `/api/admin/groups/${group.name}/roles`, { roles: ['listing'] })).statusCode, 200)
        assert.equal((await t.json('POST', '/api/admin/users', { username: 'dave', password: STRONG })).statusCode, 201)
        assert.equal((await t.json('POST', `/api/admin/groups/${group.name}/members`, { username: 'dave' })).statusCode, 201)

        const dave = await t.context.iam.getUser('dave')
        const principal = await t.context.iam.buildPrincipal(dave)
        assert.ok(principal.roles.includes('listing'), `expected the group role, got ${JSON.stringify(principal.roles)}`)
        assert.equal(await t.context.iam.authorize(principal, 's3:ListBucket', { bucket: 'ddrive' }), true)
        await assert.rejects(
            () => t.context.iam.authorize(principal, 's3:GetObject', { bucket: 'ddrive', key: 'a.txt' }),
            { code: 'AccessDenied' },
        )

        // removing the member revokes the inherited access
        assert.equal((await t.json('DELETE', `/api/admin/groups/${group.name}/members/dave`)).statusCode, 204)
        const after = await t.context.iam.buildPrincipal(await t.context.iam.getUser('dave'))
        assert.deepEqual(after.roles, [])
    } finally {
        await t.close()
    }
})

test('a Deny statement wins over an Allow statement', async () => {
    const t = await createTestServer()
    try {
        await t.json('POST', '/api/admin/users', { username: 'erin', password: STRONG })
        const role = await t.json('POST', '/api/admin/roles', {
            name: 'deny-secrets',
            policies: [
                { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:*'], Resource: ['*'] }] },
                { Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: ['s3:GetObject'], Resource: ['arn:ddrive:s3:::ddrive/secret/*'] }] },
            ],
        })
        assert.equal(role.statusCode, 201, role.body)
        await t.json('PATCH', '/api/admin/users/erin', { roles: ['deny-secrets'] })

        const principal = await t.context.iam.buildPrincipal(await t.context.iam.getUser('erin'))
        assert.equal(await t.context.iam.authorize(principal, 's3:GetObject', { bucket: 'ddrive', key: 'public/x.txt' }), true)
        await assert.rejects(
            () => t.context.iam.authorize(principal, 's3:GetObject', { bucket: 'ddrive', key: 'secret/x.txt' }),
            { code: 'AccessDenied' },
        )
    } finally {
        await t.close()
    }
})

test('the bootstrap admin is unrestricted and anonymous callers are denied', async () => {
    const t = await createTestServer()
    try {
        const admin = await t.context.iam.buildPrincipal(await t.context.iam.getUser('admin'))
        assert.equal(admin.isAdmin, true)
        for (const action of ['s3:GetObject', 's3:DeleteBucket', 'ddrive:ManageIam', 'anything:AtAll']) {
            assert.equal(await t.context.iam.authorize(admin, action, { bucket: 'ddrive', key: 'x' }), true)
        }

        const anonymous = t.context.iam.anonymousPrincipal()
        await assert.rejects(
            () => t.context.iam.authorize(anonymous, 's3:GetObject', { bucket: 'ddrive', key: 'x' }),
            { code: 'AccessDenied' },
        )
        await assert.rejects(() => t.context.iam.authorize(null, 's3:GetObject', { bucket: 'ddrive' }), { code: 'AccessDenied' })
    } finally {
        await t.close()
    }
})

test('share tokens expose exactly one object and stop working once revoked', async () => {
    const t = await createTestServer()
    try {
        await t.json('POST', '/api/buckets', { name: 'iam-bucket' })
        const write = (path, content) => t.http.inject({
            method: 'PUT',
            url: `/api/buckets/iam-bucket/objects/${path}`,
            headers: { authorization: t.basic, 'content-type': 'text/plain' },
            payload: content,
        })
        await write('public.txt', 'public bit')
        await write('private.txt', 'private bit')

        const share = t.body(await t.json('POST', '/api/buckets/iam-bucket/shares', { path: 'public.txt', maxDownloads: 5 }))
        assert.ok(share.token)

        const fetched = await t.http.inject({ method: 'GET', url: `/share/${share.token}` })
        assert.equal(fetched.statusCode, 200)
        assert.equal(fetched.body, 'public bit')

        // the token cannot be walked sideways to another key
        const escape = await t.http.inject({ method: 'GET', url: `/share/${share.token}/../private.txt` })
        assert.notEqual(escape.body, 'private bit')
        assert.equal((await t.http.inject({ method: 'GET', url: '/share/unknown-token' })).statusCode, 404)

        assert.equal((await t.json('DELETE', `/api/shares/${share.token}`)).statusCode, 204)
        assert.equal((await t.http.inject({ method: 'GET', url: `/share/${share.token}` })).statusCode, 404)
    } finally {
        await t.close()
    }
})
