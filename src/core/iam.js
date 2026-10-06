/**
 * IAM: users, groups, roles, policy documents, access keys and the
 * authorization engine.
 *
 * Policy documents follow the AWS IAM grammar (Version / Statement with
 * Effect, Action, Resource, Condition) which makes them familiar to operators
 * and directly reusable in DDrive's S3 API.
 *
 *   {
 *     "Version": "2012-10-17",
 *     "Statement": [
 *       { "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:ddrive:s3:::media/*"] }
 *     ]
 *   }
 *
 * Evaluation order: explicit Deny > explicit Allow > (optional) bucket policy
 * Allow > default Deny. Administrators bypass evaluation.
 */
const { randomUUID } = require('crypto')
const util = require('../lib/util')
const { errors } = require('../lib/errors')

const ACTIONS = [
    's3:CreateBucket', 's3:DeleteBucket', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:GetBucketLocation',
    's3:GetBucketVersioning', 's3:PutBucketVersioning', 's3:GetBucketPolicy', 's3:PutBucketPolicy', 's3:DeleteBucketPolicy',
    's3:GetBucketObjectLockConfiguration', 's3:PutBucketObjectLockConfiguration', 's3:GetBucketTagging', 's3:PutBucketTagging',
    's3:GetLifecycleConfiguration', 's3:PutLifecycleConfiguration', 's3:GetReplicationConfiguration', 's3:PutReplicationConfiguration',
    's3:GetObject', 's3:GetObjectVersion', 's3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion', 's3:AbortMultipartUpload',
    's3:ListMultipartUploadParts', 's3:ListBucketMultipartUploads', 's3:RestoreObject', 's3:GetObjectTagging', 's3:PutObjectTagging',
    's3:DeleteObjectTagging', 's3:GetObjectRetention', 's3:PutObjectRetention', 's3:GetObjectLegalHold', 's3:PutObjectLegalHold',
    's3:BypassGovernanceRetention', 's3:GetObjectAcl', 's3:PutObjectAcl', 's3:GetObjectAttributes', 's3:ReplicateObject',
    'ddrive:ListAudit', 'ddrive:VerifyAudit', 'ddrive:ReadMetrics', 'ddrive:ManageUsers', 'ddrive:ManageRoles',
    'ddrive:ManageEvents', 'ddrive:ManageLifecycle', 'ddrive:ManageReplication', 'ddrive:ManageTiering', 'ddrive:ManageShares',
    'ddrive:ReadSettings', 'ddrive:WriteSettings', 'ddrive:RunLifecycle', 'ddrive:RedriveEvents', 'webdav:Read', 'webdav:Write',
]
const ACTION_WILDCARDS = ['*', 's3:*', 'ddrive:*', 'webdav:*']

const CONDITION_KEYS = ['aws:SourceIp', 'aws:SecureTransport', 'aws:UserAgent', 'aws:RequestedRegion', 's3:prefix', 'ddrive:protocol', 'ddrive:time']

const ipInCidr = (ip, cidr) => {
    if (!ip) return false
    if (cidr === '*') return true
    if (!cidr.includes('/')) return ip === cidr
    const [range, bitsRaw] = cidr.split('/')
    const bits = Number(bitsRaw)
    const toLong = (value) => String(value).split('.').reduce((acc, part) => (acc << 8) + (Number(part) & 255), 0) >>> 0
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0
    const isV4 = (value) => /^\d+\.\d+\.\d+\.\d+$/.test(value)
    if (!isV4(ip) || !isV4(range)) return false

    return (toLong(ip) & mask) === (toLong(range) & mask)
}

const matchAction = (pattern, action) => {
    if (pattern === '*' || pattern === action) return true
    if (!pattern.includes('*') && !pattern.includes('?')) return false
    const regex = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i')

    return regex.test(action)
}

const matchResource = (pattern, resource) => {
    if (pattern === '*') return true
    if (pattern === resource) return true
    if (!pattern.includes('*') && !pattern.includes('?')) return false
    const regex = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`)

    return regex.test(resource)
}

const arnFor = (bucket, key) => `arn:ddrive:s3:::${bucket}${key ? `/${key}` : ''}`

const evaluateStatement = (statement, ctx) => {
    const effect = (statement.Effect || '').toLowerCase()
    if (effect !== 'allow' && effect !== 'deny') return null
    const actions = [].concat(statement.Action || [])
    if (!actions.some((a) => matchAction(a, ctx.action))) return null
    const resources = [].concat(statement.Resource || ['*'])
    if (!resources.some((r) => matchResource(r, ctx.resource))) return null
    if (statement.NotResource && [].concat(statement.NotResource).some((r) => matchResource(r, ctx.resource))) return null
    if (statement.Condition) {
        const conditions = statement.Condition
        const check = (key, expected) => {
            const value = ctx.conditions?.[key]
            const list = [].concat(expected)
            if (key === 'aws:SourceIp') return list.some((cidr) => ipInCidr(value, String(cidr)))
            if (key === 'aws:SecureTransport' || key === 'aws:SecureTransport'.toLowerCase()) {
                return list.some((v) => String(v) === String(value))
            }
            if (key.toLowerCase().endsWith('useragent')) return list.some((v) => String(value || '').includes(String(v)))
            return list.includes(String(value ?? ''))
        }
        // support both `Condition: { IpAddress: { key: [...] } }` and flat form
        const operators = ['IpAddress', 'NotIpAddress', 'StringEquals', 'StringLike', 'StringNotEquals', 'Bool']
        for (const [operator, body] of Object.entries(conditions)) {
            if (operator === 'StringEquals' || operator === 'StringLike' || operator === 'IpAddress' || operator === 'Bool') {
                for (const [key, expected] of Object.entries(body)) {
                    if (!check(key, expected)) return null
                }
            } else if (!operators.includes(operator) && typeof body === 'object') {
                for (const [key, expected] of Object.entries(body)) {
                    if (!check(key, expected)) return null
                }
            }
        }
    }

    return effect
}

/** Evaluate a set of policy documents for one action/resource pair. */
const evaluatePolicies = (documents, ctx) => {
    let allowed = false
    for (const doc of documents) {
        if (!doc) continue
        const statements = Array.isArray(doc) ? doc.flatMap((d) => d.Statement || []) : [].concat(doc.Statement || [])
        for (const statement of statements) {
            const effect = evaluateStatement(statement, ctx)
            if (effect === 'deny') return 'deny'
            if (effect === 'allow') allowed = true
        }
    }

    return allowed ? 'allow' : null
}

const createIam = (deps = {}) => {
    const { repo, crypto, logger = console, audit } = deps
    if (!repo || !crypto) throw new Error('iam requires repo and crypto')

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------
    const hashPassword = (password) => crypto.hashPassword(String(password))

    const assertPassword = (password, username) => {
        const value = String(password || '')
        if (value.length < 8) throw errors.validation('Password must be at least 8 characters long')
        if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) {
            throw errors.validation('Password must contain lower case, upper case and numeric characters')
        }
        if (username && value.toLowerCase().includes(String(username).toLowerCase())) {
            throw errors.validation('Password must not contain the username')
        }
    }

    const createUser = async (input) => {
        const username = String(input.username || '').trim()
        if (!/^[A-Za-z0-9._@-]{3,64}$/.test(username)) throw errors.validation('Username must be 3-64 characters (letters, digits, . _ @ -)')
        assertPassword(input.password, username)
        const existing = await repo.findOne('user', { username })
        if (existing) throw new errors.userExists(`User ${username} already exists`)
        const { hash, salt } = hashPassword(input.password)
        const user = await repo.insert('user', {
            username,
            passwordHash: hash,
            passwordSalt: salt,
            displayName: input.displayName || username,
            email: input.email || null,
            isAdmin: !!input.isAdmin,
            status: 'active',
            mustChangePassword: !!input.mustChangePassword,
            quotaBytes: input.quotaBytes || null,
        })
        if (input.roles) await setUserRoles(user.id, input.roles)
        await audit?.record({
            action: 'iam.user.create', actor: 'admin', actorType: 'user', resource: `user:${username}`, result: 'success', detail: { isAdmin: !!input.isAdmin },
        })

        return user
    }

    const listUsers = () => repo.find('user', {}, { orderBy: [{ column: 'username', dir: 'asc' }] })

    const getUser = async (username) => {
        const user = await repo.findOne('user', { username })
        if (!user) throw new errors.noSuchUser(`User ${username} does not exist`)

        return user
    }

    const updateUser = async (username, patch) => {
        const user = await getUser(username)
        const update = {}
        if (patch.displayName !== undefined) update.displayName = patch.displayName
        if (patch.email !== undefined) update.email = patch.email
        if (patch.status !== undefined) {
            if (!['active', 'disabled'].includes(patch.status)) throw errors.validation('status must be active or disabled')
            update.status = patch.status
        }
        if (patch.isAdmin !== undefined) update.isAdmin = !!patch.isAdmin
        if (patch.quotaBytes !== undefined) update.quotaBytes = patch.quotaBytes === null ? null : Number(patch.quotaBytes)
        if (patch.mustChangePassword !== undefined) update.mustChangePassword = !!patch.mustChangePassword
        if (patch.password !== undefined) {
            assertPassword(patch.password, username)
            const { hash, salt } = hashPassword(patch.password)
            update.passwordHash = hash
            update.passwordSalt = salt
            update.mustChangePassword = patch.mustChangePassword ?? false
        }
        if (!Object.keys(update).length) return user
        await repo.update('user', { id: user.id }, update)
        if (patch.password !== undefined) {
            await repo.update('access_key', { userId: user.id }, { status: 'active' })
        }
        await audit?.record({
            action: 'iam.user.update', actor: 'admin', actorType: 'user', resource: `user:${username}`, detail: { fields: Object.keys(update) },
        })

        return repo.findOne('user', { id: user.id })
    }

    const deleteUser = async (username) => {
        const user = await getUser(username)
        await repo.delete('access_key', { userId: user.id })
        await repo.delete('group_member', { userId: user.id })
        await repo.delete('principal_role', { principalType: 'user', principalId: user.id })
        await repo.delete('user', { id: user.id })
        await audit?.record({ action: 'iam.user.delete', actor: 'admin', actorType: 'user', resource: `user:${username}` })

        return true
    }

    const verifyPassword = async (username, password) => {
        const user = await repo.findOne('user', { username })
        if (!user || user.status !== 'active') return null
        if (!crypto.verifyPassword(password, user.passwordHash, user.passwordSalt)) return null
        await repo.update('user', { id: user.id }, { lastLoginAt: new Date() })

        return user
    }

    // ------------------------------------------------------------------
    // Groups, roles, policies
    // ------------------------------------------------------------------
    const createGroup = async (input) => {
        const name = String(input.name || '').trim()
        if (!name) throw errors.validation('Group name is required')

        return repo.insert('principal_group', { name, description: input.description || null })
    }

    const listGroups = () => repo.find('principal_group', {}, { orderBy: [{ column: 'name', dir: 'asc' }] })
    const deleteGroup = async (name) => {
        const group = await repo.findOne('principal_group', { name })
        if (!group) throw errors.noSuchGroup(name)
        await repo.delete('group_member', { groupId: group.id })
        await repo.delete('principal_role', { principalType: 'group', principalId: group.id })
        await repo.delete('principal_group', { id: group.id })

        return true
    }

    const addGroupMember = async (groupName, username) => {
        const group = await repo.findOne('principal_group', { name: groupName })
        const user = await getUser(username)
        if (!group) throw errors.noSuchGroup(groupName)
        const existing = await repo.findOne('group_member', { groupId: group.id, userId: user.id })
        if (existing) return existing

        return repo.insert('group_member', { groupId: group.id, userId: user.id })
    }

    const removeGroupMember = async (groupName, username) => {
        const group = await repo.findOne('principal_group', { name: groupName })
        const user = await getUser(username)
        if (!group) throw errors.noSuchGroup(groupName)

        return repo.delete('group_member', { groupId: group.id, userId: user.id })
    }

    const BUILTIN_POLICIES = {
        AdministratorAccess: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: ['*'], Resource: ['*'] }],
        },
        ReadOnlyAccess: {
            Version: '2012-10-17',
            Statement: [
                { Effect: 'Allow', Action: ['s3:GetObject', 's3:GetObjectVersion', 's3:ListBucket', 's3:ListAllMyBuckets', 's3:GetBucketLocation', 's3:GetBucketVersioning', 's3:GetObjectTagging', 's3:GetObjectAttributes', 'webdav:Read'], Resource: ['*'] },
                { Effect: 'Allow', Action: ['ddrive:ReadMetrics'], Resource: ['*'] },
            ],
        },
        ObjectWriteAccess: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:ListBucket', 's3:AbortMultipartUpload', 's3:PutObjectTagging', 'webdav:Read', 'webdav:Write'], Resource: ['*'] }],
        },
        AuditorAccess: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: ['ddrive:ListAudit', 'ddrive:VerifyAudit', 'ddrive:ReadMetrics', 's3:GetObject', 's3:ListBucket', 'webdav:Read'], Resource: ['*'] }],
        },
        ComplianceOfficer: {
            Version: '2012-10-17',
            Statement: [
                { Effect: 'Allow', Action: ['s3:GetObjectRetention', 's3:PutObjectRetention', 's3:GetObjectLegalHold', 's3:PutObjectLegalHold', 's3:BypassGovernanceRetention', 's3:GetBucketObjectLockConfiguration', 's3:PutBucketObjectLockConfiguration', 'ddrive:ListAudit', 'ddrive:VerifyAudit'], Resource: ['*'] },
                { Effect: 'Deny', Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'], Resource: ['*'] },
            ],
        },
        ReplicationOperator: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: ['ddrive:ManageReplication', 's3:ReplicateObject', 's3:GetObject', 's3:ListBucket', 'ddrive:ReadMetrics'], Resource: ['*'] }],
        },
        StorageAdministrator: {
            Version: '2012-10-17',
            Statement: [
                { Effect: 'Allow', Action: ['s3:*', 'ddrive:ManageLifecycle', 'ddrive:ManageTiering', 'ddrive:ManageEvents', 'ddrive:ManageShares', 'ddrive:RunLifecycle', 'ddrive:ReadMetrics'], Resource: ['*'] },
                { Effect: 'Deny', Action: ['ddrive:ManageUsers', 'ddrive:ManageRoles', 'ddrive:WriteSettings'], Resource: ['*'] },
            ],
        },
        BucketPolicyDenyInsecureTransport: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Deny', Action: ['s3:*'], Resource: ['*'], Condition: { Bool: { 'aws:SecureTransport': 'false' } } }],
        },
    }

    const seedBuiltinPolicies = async () => {
        for (const [name, document] of Object.entries(BUILTIN_POLICIES)) {
            // eslint-disable-next-line no-await-in-loop
            const existing = await repo.findOne('policy', { name })
            // eslint-disable-next-line no-await-in-loop
            if (!existing) {
                // eslint-disable-next-line no-await-in-loop
                await repo.insert('policy', {
                    name, document, system: true, description: `Built-in DDrive policy: ${name}`,
                })
            }
        }
    }

    const listPolicies = () => repo.find('policy', {}, { orderBy: [{ column: 'name', dir: 'asc' }] })
    const getPolicy = async (name) => {
        const policy = await repo.findOne('policy', { name })
        if (!policy) throw errors.noSuchPolicy(name)

        return policy
    }
    const createPolicy = async (input) => {
        validatePolicyDocument(input.document)

        return repo.insert('policy', {
            name: input.name, document: input.document, description: input.description || null, system: false,
        })
    }
    const updatePolicy = async (name, document) => {
        validatePolicyDocument(document)

        return repo.update('policy', { name }, { document })
    }
    const deletePolicy = async (name) => {
        const policy = await getPolicy(name)
        if (policy.system) throw errors.validation(`Built-in policy ${name} cannot be deleted`)

        return repo.delete('policy', { id: policy.id })
    }

    const validatePolicyDocument = (document) => {
        if (!document || typeof document !== 'object') throw errors.validation('Policy document must be a JSON object')
        const statements = [].concat(document.Statement || [])
        if (!statements.length) throw errors.validation('Policy document must contain at least one statement')
        statements.forEach((statement) => {
            if (!['Allow', 'Deny'].includes(statement.Effect)) throw errors.validation('Each statement needs an Effect of Allow or Deny')
            if (!statement.Action) throw errors.validation('Each statement needs an Action')
            if (!statement.Resource) throw errors.validation('Each statement needs a Resource')
        })
        const unknownActions = [].concat(document.Statement).flatMap((s) => [].concat(s.Action))
            .filter((a) => !ACTIONS.includes(a) && !ACTION_WILDCARDS.includes(a) && !a.includes('*'))
        if (unknownActions.length) throw errors.validation(`Unknown actions: ${unknownActions.join(', ')}`)

        return true
    }

    const listRoles = () => repo.find('role', {}, { orderBy: [{ column: 'name', dir: 'asc' }] })
    const createRole = async (input) => {
        const policies = (input.policies || []).map((p) => (typeof p === 'string' ? { name: p } : p))

        return repo.insert('role', {
            name: input.name,
            description: input.description || null,
            policies,
            system: !!input.system,
        })
    }
    const updateRole = (name, patch) => {
        const update = {}
        if (patch.description !== undefined) update.description = patch.description
        if (patch.policies !== undefined) update.policies = patch.policies

        return repo.update('role', { name }, update)
    }
    const deleteRole = async (name) => {
        const role = await repo.findOne('role', { name })
        if (!role) throw errors.noSuchRole(name)
        if (role.system) throw errors.validation(`Built-in role ${name} cannot be deleted`)
        await repo.delete('principal_role', { roleId: role.id })
        await repo.delete('role', { id: role.id })

        return true
    }

    const seedBuiltinRoles = async () => {
        const roles = [
            { name: 'Administrators', description: 'Full administrative access', policies: [{ name: 'AdministratorAccess' }], system: true },
            { name: 'StorageUsers', description: 'Read and write objects', policies: [{ name: 'ObjectWriteAccess' }], system: true },
            { name: 'ReadOnly', description: 'Read only access to objects', policies: [{ name: 'ReadOnlyAccess' }], system: true },
            { name: 'Auditors', description: 'Audit log and metrics read access', policies: [{ name: 'AuditorAccess' }], system: true },
        ]
        for (const role of roles) {
            // eslint-disable-next-line no-await-in-loop
            const existing = await repo.findOne('role', { name: role.name })
            // eslint-disable-next-line no-await-in-loop
            if (!existing) await repo.insert('role', role)
        }
    }

    const setUserRoles = async (userId, roleNames) => {
        await repo.delete('principal_role', { principalType: 'user', principalId: userId })
        for (const roleName of roleNames) {
            // eslint-disable-next-line no-await-in-loop
            const role = await repo.findOne('role', { name: roleName })
            if (!role) throw errors.noSuchRole(roleName)
            // eslint-disable-next-line no-await-in-loop
            await repo.insert('principal_role', { principalType: 'user', principalId: userId, roleId: role.id })
        }

        return true
    }

    const setGroupRoles = async (groupId, roleNames) => {
        await repo.delete('principal_role', { principalType: 'group', principalId: groupId })
        for (const roleName of roleNames) {
            // eslint-disable-next-line no-await-in-loop
            const role = await repo.findOne('role', { name: roleName })
            if (!role) throw errors.noSuchRole(roleName)
            // eslint-disable-next-line no-await-in-loop
            await repo.insert('principal_role', { principalType: 'group', principalId: groupId, roleId: role.id })
        }

        return true
    }

    /** All policy documents that apply to a user (direct roles + group roles). */
    const policiesForUser = async (userId) => {
        const memberships = await repo.find('group_member', { userId })
        const bindings = await repo.find('principal_role', { principalType: 'user', principalId: userId })
        const groupBindings = memberships.length
            ? await repo.find('principal_role', { principalType: 'group', principalId: { in: memberships.map((m) => m.groupId) } })
            : []
        const roleIds = [...new Set([...bindings, ...groupBindings].map((b) => b.roleId))]
        if (!roleIds.length) return { documents: [], roles: [] }
        const roles = await repo.find('role', { id: { in: roleIds } })
        const policyNames = [...new Set(roles.flatMap((r) => (r.policies || []).map((p) => p.name || p)))]
        const documents = []
        for (const name of policyNames) {
            // eslint-disable-next-line no-await-in-loop
            const policy = await repo.findOne('policy', { name })
            if (policy) documents.push(policy.document)
        }
        const inlineStatements = roles.flatMap((r) => (r.policies || []).filter((p) => p.Statement))
        documents.push(...inlineStatements)

        return { documents, roles: roles.map((r) => r.name) }
    }

    // ------------------------------------------------------------------
    // Access keys
    // ------------------------------------------------------------------
    const createAccessKey = async (username, opts = {}) => {
        const user = await getUser(username)
        const accessKeyId = `DD${util.randomHex(8).toUpperCase()}`
        const secretAccessKey = util.randomToken(30)
        const encrypted = await crypto.encryptSecret(secretAccessKey)
        const row = await repo.insert('access_key', {
            accessKeyId,
            secretEnc: encrypted.value,
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            keyId: encrypted.keyId,
            userId: user.id,
            description: opts.description || null,
            expiresAt: opts.expiresAt ? new Date(opts.expiresAt) : null,
        })
        await audit?.record({
            action: 'iam.access_key.create', actor: 'admin', actorType: 'user', resource: `access-key:${accessKeyId}`, detail: { username },
        })

        return { ...row, secretAccessKey, accessKeyId }
    }

    const listAccessKeys = async (username) => {
        if (!username) return repo.find('access_key', {}, { orderBy: [{ column: 'createdAt', dir: 'desc' }] })
        const user = await getUser(username)

        return repo.find('access_key', { userId: user.id }, { orderBy: [{ column: 'createdAt', dir: 'desc' }] })
    }

    const rotateAccessKey = async (accessKeyId) => {
        const key = await repo.findOne('access_key', { accessKeyId })
        if (!key) throw errors.validation(`Access key ${accessKeyId} does not exist`)
        const secretAccessKey = util.randomToken(30)
        const encrypted = await crypto.encryptSecret(secretAccessKey)
        await repo.update('access_key', { id: key.id }, {
            secretEnc: encrypted.value, iv: encrypted.iv, authTag: encrypted.authTag, keyId: encrypted.keyId,
        })
        await audit?.record({ action: 'iam.access_key.rotate', actor: 'admin', actorType: 'user', resource: `access-key:${accessKeyId}` })

        return { accessKeyId, secretAccessKey }
    }

    const updateAccessKey = async (accessKeyId, patch) => repo.update('access_key', { accessKeyId }, patch)

    const deleteAccessKey = async (accessKeyId) => {
        await audit?.record({ action: 'iam.access_key.delete', actor: 'admin', actorType: 'user', resource: `access-key:${accessKeyId}` })

        return repo.delete('access_key', { accessKeyId })
    }

    /** Resolve a SigV4 access key id to its secret + principal. */
    const resolveAccessKey = async (accessKeyId) => {
        const key = await repo.findOne('access_key', { accessKeyId })
        if (!key || key.status !== 'active') return null
        if (key.expiresAt && new Date(key.expiresAt).getTime() < Date.now()) return null
        const secretAccessKey = await crypto.decryptSecret({ value: key.secretEnc, iv: key.iv, authTag: key.authTag })

        return { key, secretAccessKey }
    }

    // ------------------------------------------------------------------
    // Authorization
    // ------------------------------------------------------------------
    /**
     * @param {object} principal { id, name, type: 'user'|'anonymous'|'system', isAdmin, documents, roles }
     * @param {string} action    e.g. s3:GetObject
     * @param {object} resource  { bucket, key, bucketId }
     * @param {object} [ctx]     conditions (ip, secure, userAgent, protocol)
     * @param {object} [bucketPolicy] parsed bucket policy document (optional)
     */
    const authorize = async (principal, action, resource, ctx = {}, bucketPolicy) => {
        if (!principal) throw errors.accessDenied()
        if (principal.isAdmin) return true

        const resourceArn = resource.arn || arnFor(resource.bucket, resource.key)
        const evaluationCtx = {
            action,
            resource: resourceArn,
            conditions: {
                'aws:SourceIp': ctx.ip,
                'aws:SecureTransport': ctx.secure ? 'true' : 'false',
                'aws:UserAgent': ctx.userAgent,
                'aws:RequestedRegion': ctx.region,
                'ddrive:protocol': ctx.protocol,
            },
        }
        const documents = [...(principal.documents || [])]
        if (bucketPolicy) documents.push(bucketPolicy)
        const decision = evaluatePolicies(documents, evaluationCtx)
        if (decision === 'deny') {
            await audit?.record({
                action: 'authz.denied', actor: principal.name, actorId: principal.id, actorType: principal.type,
                resource: resourceArn, result: 'denied', protocol: ctx.protocol, ip: ctx.ip, requestId: ctx.requestId,
                detail: { action },
            })

            throw errors.accessDenied(`Not authorized to perform ${action} on ${resourceArn}`)
        }
        if (decision === 'allow') return true
        // Default deny, but keep the historical "public access" modes working:
        // READ_ONLY_FILE open downloads, READ_ONLY_PANEL read only panel access.
        if (ctx.publicAccess === 'READ_ONLY_FILE' && ['s3:GetObject', 's3:GetObjectVersion', 'webdav:Read'].includes(action)) return true
        if (ctx.publicAccess === 'READ_ONLY_PANEL' && action.startsWith('s3:Get')) return true
        await audit?.record({
            action: 'authz.denied', actor: principal.name, actorId: principal.id, actorType: principal.type,
            resource: resourceArn, result: 'denied', protocol: ctx.protocol, ip: ctx.ip, requestId: ctx.requestId,
            detail: { action },
        })

        throw errors.accessDenied(`Not authorized to perform ${action} on ${resourceArn}`)
    }

    const anonymousPrincipal = () => ({
        id: null, name: 'anonymous', type: 'anonymous', isAdmin: false, documents: [],
    })

    const buildPrincipal = async (user, opts = {}) => {
        const { documents, roles } = await policiesForUser(user.id)

        return {
            id: user.id,
            name: user.username,
            displayName: user.displayName || user.username,
            type: opts.type || 'user',
            isAdmin: !!user.isAdmin,
            documents,
            roles,
            mustChangePassword: !!user.mustChangePassword,
            mfaEnabled: !!user.mfaEnabled,
        }
    }

    return {
        ACTIONS,
        BUILTIN_POLICIES,
        hashPassword,
        assertPassword,
        createUser,
        listUsers,
        getUser,
        updateUser,
        deleteUser,
        verifyPassword,
        createGroup,
        listGroups,
        deleteGroup,
        addGroupMember,
        removeGroupMember,
        setUserRoles,
        setGroupRoles,
        policiesForUser,
        listPolicies,
        getPolicy,
        createPolicy,
        updatePolicy,
        deletePolicy,
        validatePolicyDocument,
        seedBuiltinPolicies,
        seedBuiltinRoles,
        listRoles,
        createRole,
        updateRole,
        deleteRole,
        createAccessKey,
        listAccessKeys,
        rotateAccessKey,
        updateAccessKey,
        deleteAccessKey,
        resolveAccessKey,
        authorize,
        buildPrincipal,
        anonymousPrincipal,
        arnFor,
        evaluatePolicies,
        matchAction,
        ipInCidr,
        randomUUID,
    }
}

module.exports = {
    createIam, ACTIONS, arnFor, evaluatePolicies, matchAction, CONDITION_KEYS,
}
