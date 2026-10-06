/**
 * DDrive schema definition (single source of truth).
 *
 * The same declarative schema is used to:
 *  - generate DDL for every supported dialect (see `./ddl.js`)
 *  - hydrate/serialize rows in the repository (JSON/TIMESTAMP/BOOLEAN codecs)
 *  - validate column names before they reach SQL
 *
 * Column types
 *   uuid   -> uuid (pg) / text (sqlite)
 *   text   -> text
 *   int    -> integer
 *   bigint -> bigint
 *   bool   -> boolean / integer(0,1)
 *   json   -> jsonb (pg) / text (sqlite)
 *   ts     -> timestamptz (pg) / text ISO-8601 (sqlite)
 *   serial -> bigserial (pg) / integer primary key autoincrement (sqlite)
 */

const PK = { type: 'uuid', primary: true, notNull: true, default: 'UUID' }

const TS = { type: 'ts', notNull: true, default: 'NOW' }
const CREATED_AT = { ...TS }
const UPDATED_AT = { ...TS }

const tables = {
    // ------------------------------------------------------------------
    // Namespace / buckets
    // ------------------------------------------------------------------
    bucket: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true, unique: true },
            region: { type: 'text', notNull: true, default: 'primary' },
            ownerId: { type: 'uuid' },
            // off | enabled | suspended (S3 semantics)
            versioning: { type: 'text', notNull: true, default: 'off' },
            objectLockEnabled: { type: 'bool', notNull: true, default: false },
            // GOVERNANCE | COMPLIANCE
            defaultRetentionMode: { type: 'text' },
            defaultRetentionDays: { type: 'int' },
            defaultLegalHold: { type: 'bool', notNull: true, default: false },
            defaultStorageClass: { type: 'text', notNull: true, default: 'STANDARD' },
            quotaBytes: { type: 'bigint' },
            tags: { type: 'json' },
            metadata: { type: 'json' },
            cors: { type: 'json' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'bucket_name_idx', columns: ['name'] },
        ],
    },

    // ------------------------------------------------------------------
    // Objects (directories + files). Versioning lives in object_version.
    // ------------------------------------------------------------------
    directory: {
        columns: {
            id: PK,
            bucketId: { type: 'uuid' },
            name: { type: 'text', notNull: true },
            parentId: { type: 'uuid' },
            // full key path inside the bucket ('' for the bucket root)
            path: { type: 'text', default: '' },
            depth: { type: 'int', default: 0 },
            // directory | file
            type: { type: 'text', notNull: true, default: 'directory' },
            size: { type: 'bigint', default: 0 },
            etag: { type: 'text' },
            contentType: { type: 'text' },
            storageClass: { type: 'text', default: 'STANDARD' },
            metadata: { type: 'json' },
            tags: { type: 'json' },
            ownerId: { type: 'uuid' },
            createdBy: { type: 'text' },
            latestVersionId: { type: 'uuid' },
            versioning: { type: 'text', default: 'inherit' },
            lockMode: { type: 'text' },
            lockUntil: { type: 'ts' },
            legalHold: { type: 'bool', default: false },
            checksum: { type: 'text' },
            deletedAt: { type: 'ts' },
            accessCount: { type: 'int', default: 0 },
            lastAccessAt: { type: 'ts' },
            bytesServed: { type: 'bigint', default: 0 },
            replicationStatus: { type: 'text', default: 'none' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        uniques: [
            { name: 'directory_name_parent_unique', columns: ['name', 'parentId'] },
        ],
        indexes: [
            { name: 'directory_parent_id_idx', columns: ['parentId'] },
            { name: 'directory_bucket_path_idx', columns: ['bucketId', 'path'] },
            { name: 'directory_path_idx', columns: ['path'] },
            { name: 'directory_bucket_parent_idx', columns: ['bucketId', 'parentId'] },
            { name: 'directory_bucket_deleted_idx', columns: ['bucketId', 'deletedAt'] },
            { name: 'directory_latest_version_idx', columns: ['latestVersionId'] },
            { name: 'directory_type_idx', columns: ['type'] },
        ],
    },

    object_version: {
        columns: {
            id: PK,
            objectId: { type: 'uuid', notNull: true },
            bucketId: { type: 'uuid', notNull: true },
            path: { type: 'text' },
            versionNumber: { type: 'int', notNull: true, default: 1 },
            isLatest: { type: 'bool', notNull: true, default: true },
            isDeleteMarker: { type: 'bool', notNull: true, default: false },
            size: { type: 'bigint', default: 0 },
            etag: { type: 'text' },
            checksum: { type: 'text' },
            contentType: { type: 'text' },
            metadata: { type: 'json' },
            tags: { type: 'json' },
            storageClass: { type: 'text', default: 'STANDARD' },
            // HOT | COOL | ARCHIVE
            tier: { type: 'text', default: 'HOT' },
            tieredAt: { type: 'ts' },
            encAlg: { type: 'text' },
            keyId: { type: 'text' },
            wrappedDek: { type: 'text' },
            createdBy: { type: 'text' },
            ownerId: { type: 'uuid' },
            retentionMode: { type: 'text' },
            retainUntil: { type: 'ts' },
            legalHold: { type: 'bool', default: false },
            expiresAt: { type: 'ts' },
            replicationStatus: { type: 'text', default: 'none' },
            createdAt: CREATED_AT,
        },
        uniques: [
            { name: 'object_version_number_unique', columns: ['objectId', 'versionNumber'] },
        ],
        indexes: [
            { name: 'object_version_object_idx', columns: ['objectId', 'versionNumber'] },
            { name: 'object_version_latest_idx', columns: ['objectId', 'isLatest'] },
            { name: 'object_version_bucket_idx', columns: ['bucketId'] },
            { name: 'object_version_bucket_path_idx', columns: ['bucketId', 'path'] },
            { name: 'object_version_expiry_idx', columns: ['expiresAt'] },
        ],
    },

    // Chunks (S3 parts / Discord attachments / local files / multipart parts)
    block: {
        columns: {
            id: PK,
            fileId: { type: 'uuid' },
            versionId: { type: 'uuid' },
            uploadId: { type: 'uuid' },
            partNumber: { type: 'int' },
            ordinal: { type: 'int' },
            url: { type: 'text', notNull: true },
            size: { type: 'bigint', notNull: true },
            iv: { type: 'text' },
            wrappedDek: { type: 'text' },
            keyId: { type: 'text' },
            encAlg: { type: 'text' },
            checksum: { type: 'text' },
            // local | discord | s3 | memory
            backend: { type: 'text', default: 'local' },
            tier: { type: 'text', default: 'HOT' },
            migratedAt: { type: 'ts' },
            createdAt: CREATED_AT,
        },
        indexes: [
            { name: 'block_file_idx', columns: ['fileId'] },
            { name: 'block_version_ordinal_idx', columns: ['versionId', 'ordinal'] },
            { name: 'block_upload_part_idx', columns: ['uploadId', 'partNumber', 'ordinal'] },
        ],
    },

    multipart_upload: {
        columns: {
            id: PK,
            bucketId: { type: 'uuid', notNull: true },
            parentId: { type: 'uuid' },
            name: { type: 'text', notNull: true },
            contentType: { type: 'text' },
            metadata: { type: 'json' },
            tags: { type: 'json' },
            storageClass: { type: 'text' },
            ownerId: { type: 'uuid' },
            createdBy: { type: 'text' },
            encAlg: { type: 'text' },
            keyId: { type: 'text' },
            // in-progress | completed | aborted
            status: { type: 'text', notNull: true, default: 'in-progress' },
            createdAt: CREATED_AT,
            completedAt: { type: 'ts' },
            expiresAt: { type: 'ts' },
        },
        indexes: [
            { name: 'multipart_bucket_status_idx', columns: ['bucketId', 'status'] },
            { name: 'multipart_expiry_idx', columns: ['expiresAt'] },
        ],
    },

    multipart_part: {
        columns: {
            id: PK,
            uploadId: { type: 'uuid', notNull: true },
            partNumber: { type: 'int', notNull: true },
            size: { type: 'bigint', notNull: true },
            etag: { type: 'text', notNull: true },
            checksum: { type: 'text' },
            createdAt: CREATED_AT,
        },
        uniques: [
            { name: 'multipart_part_unique', columns: ['uploadId', 'partNumber'] },
        ],
        indexes: [
            { name: 'multipart_part_upload_idx', columns: ['uploadId'] },
        ],
    },

    webdav_lock: {
        columns: {
            id: PK,
            token: { type: 'text', notNull: true, unique: true },
            bucketId: { type: 'uuid', notNull: true },
            path: { type: 'text', notNull: true },
            principalId: { type: 'uuid' },
            ownerXml: { type: 'text' },
            // exclusive | shared
            scope: { type: 'text', notNull: true, default: 'exclusive' },
            type: { type: 'text', notNull: true, default: 'write' },
            // 0 | infinity
            depth: { type: 'text', notNull: true, default: 'infinity' },
            timeoutSeconds: { type: 'int', notNull: true, default: 3600 },
            root: { type: 'bool', default: true },
            createdAt: CREATED_AT,
            expiresAt: { type: 'ts', notNull: true },
        },
        indexes: [
            { name: 'webdav_lock_path_idx', columns: ['bucketId', 'path'] },
            { name: 'webdav_lock_expiry_idx', columns: ['expiresAt'] },
        ],
    },

    share_link: {
        columns: {
            id: PK,
            objectId: { type: 'uuid' },
            bucketId: { type: 'uuid' },
            token: { type: 'text', notNull: true, unique: true },
            path: { type: 'text' },
            permission: { type: 'text', notNull: true, default: 'read' },
            passwordHash: { type: 'text' },
            passwordSalt: { type: 'text' },
            expiresAt: { type: 'ts' },
            maxDownloads: { type: 'int' },
            downloads: { type: 'int', notNull: true, default: 0 },
            createdBy: { type: 'text' },
            createdAt: CREATED_AT,
            lastAccessAt: { type: 'ts' },
        },
        indexes: [
            { name: 'share_link_object_idx', columns: ['objectId'] },
        ],
    },

    object_tag: {
        columns: {
            id: PK,
            objectId: { type: 'uuid', notNull: true },
            versionId: { type: 'uuid' },
            bucketId: { type: 'uuid' },
            key: { type: 'text', notNull: true },
            value: { type: 'text', notNull: true },
            // user | ai | system
            source: { type: 'text', notNull: true, default: 'user' },
            createdAt: CREATED_AT,
        },
        uniques: [
            { name: 'object_tag_unique', columns: ['objectId', 'key'] },
        ],
        indexes: [
            { name: 'object_tag_key_value_idx', columns: ['key', 'value'] },
            { name: 'object_tag_bucket_idx', columns: ['bucketId'] },
        ],
    },

    bucket_policy: {
        columns: {
            id: PK,
            bucketId: { type: 'uuid', notNull: true },
            name: { type: 'text' },
            document: { type: 'json', notNull: true },
            createdBy: { type: 'text' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'bucket_policy_bucket_idx', columns: ['bucketId'] },
        ],
    },

    // ------------------------------------------------------------------
    // IAM
    // ------------------------------------------------------------------
    user: {
        columns: {
            id: PK,
            username: { type: 'text', notNull: true, unique: true },
            passwordHash: { type: 'text' },
            passwordSalt: { type: 'text' },
            displayName: { type: 'text' },
            email: { type: 'text' },
            status: { type: 'text', notNull: true, default: 'active' },
            isAdmin: { type: 'bool', notNull: true, default: false },
            mustChangePassword: { type: 'bool', notNull: true, default: false },
            quotaBytes: { type: 'bigint' },
            usedBytes: { type: 'bigint', notNull: true, default: 0 },
            mfaEnabled: { type: 'bool', notNull: true, default: false },
            mfaSecret: { type: 'text' },
            lastLoginAt: { type: 'ts' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'user_username_idx', columns: ['username'] },
        ],
    },

    principal_group: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true, unique: true },
            description: { type: 'text' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
    },

    group_member: {
        columns: {
            id: PK,
            groupId: { type: 'uuid', notNull: true },
            userId: { type: 'uuid', notNull: true },
            createdAt: CREATED_AT,
        },
        uniques: [
            { name: 'group_member_unique', columns: ['groupId', 'userId'] },
        ],
    },

    role: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true, unique: true },
            description: { type: 'text' },
            policies: { type: 'json' },
            system: { type: 'bool', notNull: true, default: false },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
    },

    policy: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true, unique: true },
            description: { type: 'text' },
            document: { type: 'json', notNull: true },
            system: { type: 'bool', notNull: true, default: false },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
    },

    principal_role: {
        columns: {
            id: PK,
            principalType: { type: 'text', notNull: true },
            principalId: { type: 'uuid', notNull: true },
            roleId: { type: 'uuid', notNull: true },
            bucketId: { type: 'uuid' },
            createdAt: CREATED_AT,
        },
        indexes: [
            { name: 'principal_role_principal_idx', columns: ['principalType', 'principalId'] },
            { name: 'principal_role_role_idx', columns: ['roleId'] },
        ],
    },

    access_key: {
        columns: {
            id: PK,
            accessKeyId: { type: 'text', notNull: true, unique: true },
            secretEnc: { type: 'text', notNull: true },
            iv: { type: 'text' },
            authTag: { type: 'text' },
            keyId: { type: 'text' },
            userId: { type: 'uuid', notNull: true },
            status: { type: 'text', notNull: true, default: 'active' },
            description: { type: 'text' },
            expiresAt: { type: 'ts' },
            lastUsedAt: { type: 'ts' },
            lastUsedIp: { type: 'text' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'access_key_user_idx', columns: ['userId'] },
            { name: 'access_key_status_idx', columns: ['status'] },
        ],
    },

    // ------------------------------------------------------------------
    // Audit (append-only, hash chained)
    // ------------------------------------------------------------------
    audit_event: {
        columns: {
            seq: { type: 'serial', primary: true },
            id: { type: 'uuid', notNull: true, unique: true },
            ts: TS,
            actor: { type: 'text' },
            actorId: { type: 'uuid' },
            actorType: { type: 'text' },
            action: { type: 'text', notNull: true },
            resource: { type: 'text' },
            resourceType: { type: 'text' },
            bucket: { type: 'text' },
            bucketId: { type: 'uuid' },
            objectKey: { type: 'text' },
            versionId: { type: 'uuid' },
            // success | denied | error
            result: { type: 'text', notNull: true, default: 'success' },
            statusCode: { type: 'int' },
            ip: { type: 'text' },
            userAgent: { type: 'text' },
            requestId: { type: 'text' },
            protocol: { type: 'text' },
            detail: { type: 'json' },
            prevHash: { type: 'text' },
            hash: { type: 'text' },
        },
        indexes: [
            { name: 'audit_event_ts_idx', columns: ['ts'] },
            { name: 'audit_event_action_idx', columns: ['action'] },
            { name: 'audit_event_bucket_idx', columns: ['bucket'] },
            { name: 'audit_event_actor_idx', columns: ['actor'] },
        ],
    },

    // ------------------------------------------------------------------
    // Cross region replication
    // ------------------------------------------------------------------
    replication_peer: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true, unique: true },
            endpoint: { type: 'text', notNull: true },
            region: { type: 'text' },
            bucket: { type: 'text' },
            accessKeyId: { type: 'text' },
            secretEnc: { type: 'text' },
            iv: { type: 'text' },
            authTag: { type: 'text' },
            keyId: { type: 'text' },
            direction: { type: 'text', notNull: true, default: 'outbound' },
            prefix: { type: 'text' },
            status: { type: 'text', notNull: true, default: 'enabled' },
            verifyTls: { type: 'bool', notNull: true, default: true },
            // ddrive (native replication API) | s3 (replicate into an S3 backend)
            mode: { type: 'text', notNull: true, default: 'ddrive' },
            lastSyncAt: { type: 'ts' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
    },

    replication_task: {
        columns: {
            id: PK,
            peerId: { type: 'uuid', notNull: true },
            objectId: { type: 'uuid' },
            versionId: { type: 'uuid' },
            bucketId: { type: 'uuid' },
            // object key at enqueue time: a permanent delete removes the
            // directory row, so the path can not be looked up later
            path: { type: 'text' },
            // PUT | DELETE | META
            op: { type: 'text', notNull: true },
            // pending | in-flight | done | failed
            status: { type: 'text', notNull: true, default: 'pending' },
            priority: { type: 'int', notNull: true, default: 5 },
            attempts: { type: 'int', notNull: true, default: 0 },
            lastError: { type: 'text' },
            sizeBytes: { type: 'bigint' },
            checksum: { type: 'text' },
            nextAttemptAt: { type: 'ts' },
            completedAt: { type: 'ts' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'replication_task_status_idx', columns: ['status', 'nextAttemptAt'] },
            { name: 'replication_task_peer_idx', columns: ['peerId', 'status'] },
            { name: 'replication_task_version_idx', columns: ['versionId'] },
        ],
    },

    // ------------------------------------------------------------------
    // Management: lifecycle, tiering, tagging, events
    // ------------------------------------------------------------------
    lifecycle_rule: {
        columns: {
            id: PK,
            bucketId: { type: 'uuid' },
            name: { type: 'text', notNull: true },
            status: { type: 'text', notNull: true, default: 'Enabled' },
            prefix: { type: 'text' },
            tagKey: { type: 'text' },
            tagValue: { type: 'text' },
            minObjectSize: { type: 'bigint' },
            transitions: { type: 'json' },
            expirationDays: { type: 'int' },
            expireDeleteMarkers: { type: 'bool', default: false },
            noncurrentVersionExpirationDays: { type: 'int' },
            noncurrentVersionsToRetain: { type: 'int' },
            abortIncompleteMultipartDays: { type: 'int' },
            priority: { type: 'int', notNull: true, default: 10 },
            lastRunAt: { type: 'ts' },
            lastRunSummary: { type: 'json' },
            createdBy: { type: 'text' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'lifecycle_rule_bucket_idx', columns: ['bucketId'] },
        ],
    },

    tiering_policy: {
        columns: {
            id: PK,
            bucketId: { type: 'uuid' },
            name: { type: 'text', notNull: true },
            enabled: { type: 'bool', notNull: true, default: true },
            hotToCoolDays: { type: 'int', default: 30 },
            coolToArchiveDays: { type: 'int', default: 180 },
            minAccessCount: { type: 'int', default: 2 },
            minSizeBytes: { type: 'bigint', default: 0 },
            targetTier: { type: 'text', default: 'COOL' },
            intervalMinutes: { type: 'int', notNull: true, default: 60 },
            lastRunAt: { type: 'ts' },
            lastRunSummary: { type: 'json' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
        indexes: [
            { name: 'tiering_policy_bucket_idx', columns: ['bucketId'] },
        ],
    },

    auto_tag_rule: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true },
            enabled: { type: 'bool', notNull: true, default: true },
            bucketId: { type: 'uuid' },
            prefix: { type: 'text' },
            priority: { type: 'int', notNull: true, default: 10 },
            conditions: { type: 'json' },
            tags: { type: 'json' },
            // merge | replace
            mode: { type: 'text', notNull: true, default: 'merge' },
            // upload | sweep | both
            applyOn: { type: 'text', notNull: true, default: 'upload' },
            lastRunAt: { type: 'ts' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
    },

    event_target: {
        columns: {
            id: PK,
            name: { type: 'text', notNull: true, unique: true },
            // webhook | function
            type: { type: 'text', notNull: true, default: 'webhook' },
            url: { type: 'text', notNull: true },
            secret: { type: 'text' },
            events: { type: 'json' },
            bucketId: { type: 'uuid' },
            prefix: { type: 'text' },
            status: { type: 'text', notNull: true, default: 'enabled' },
            maxRetries: { type: 'int', notNull: true, default: 5 },
            timeoutMs: { type: 'int', notNull: true, default: 10000 },
            headers: { type: 'json' },
            createdAt: CREATED_AT,
            updatedAt: UPDATED_AT,
        },
    },

    event_delivery: {
        columns: {
            id: PK,
            targetId: { type: 'uuid', notNull: true },
            eventId: { type: 'uuid' },
            eventType: { type: 'text' },
            payload: { type: 'json' },
            // pending | delivered | failed | dead
            status: { type: 'text', notNull: true, default: 'pending' },
            attempts: { type: 'int', notNull: true, default: 0 },
            responseCode: { type: 'int' },
            lastError: { type: 'text' },
            lastAttemptAt: { type: 'ts' },
            nextAttemptAt: { type: 'ts' },
            deliveredAt: { type: 'ts' },
            createdAt: CREATED_AT,
        },
        indexes: [
            { name: 'event_delivery_status_idx', columns: ['status', 'nextAttemptAt'] },
            { name: 'event_delivery_target_idx', columns: ['targetId', 'status'] },
        ],
    },

    setting: {
        columns: {
            key: { type: 'text', primary: true, notNull: true },
            value: { type: 'json' },
            category: { type: 'text' },
            updatedBy: { type: 'text' },
            updatedAt: UPDATED_AT,
        },
    },
}

/** Columns that are JSON encoded in sqlite and object-mapped in pg. */
const JSON_TYPE = 'json'

module.exports = { tables, JSON_TYPE }
