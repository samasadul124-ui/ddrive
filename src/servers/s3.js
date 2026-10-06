/**
 * S3 compatible API.
 *
 * Supported (path-style and - when `S3_DOMAIN` is set - virtual-host style):
 *
 *   ListBuckets, CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation
 *   ListObjects (v1), ListObjectsV2, ListObjectVersions
 *   Get/Head/Put/Copy/DeleteObject, DeleteObjects (multi delete)
 *   GetObjectTagging / PutObjectTagging / DeleteObjectTagging
 *   GetObjectRetention / PutObjectRetention / GetObjectLegalHold / PutObjectLegalHold
 *   GetObjectAttributes, RestoreObject
 *   CreateMultipartUpload, UploadPart, UploadPartCopy, ListParts, ListMultipartUploads,
 *   CompleteMultipartUpload, AbortMultipartUpload
 *   GetBucketVersioning / PutBucketVersioning, Get/Put/DeleteBucketPolicy,
 *   Get/PutBucketTagging, GetObjectLockConfiguration / PutObjectLockConfiguration,
 *   Get/Put/DeleteBucketLifecycleConfiguration, Get/PutBucketReplication,
 *   GetBucketAcl, GetBucketCors, GetBucketEncryption, GetBucketLogging,
 *   GetBucketNotificationConfiguration, GetBucketAccelerateConfiguration
 *
 * Authentication is AWS Signature V4 (see lib/sigv4.js); anonymous requests are
 * only served when the bucket policy (or PUBLIC_ACCESS) allows them.
 */
const util = require('../lib/util')
const xml = require('../lib/xml')
const sigv4 = require('../lib/sigv4')
const { errors, StorageError } = require('../lib/errors')

const S3_XMLNS = 'http://s3.amazonaws.com/doc/2006-03-01/'
const OWNER_ID = 'ddrive'
const OWNER_NAME = 'ddrive'

const escape = (value) => util.escapeXml(value === undefined || value === null ? '' : String(value))
const el = (name, value) => (value === undefined || value === null ? '' : `<${name}>${escape(value)}</${name}>`)
const elRaw = (name, value) => (value === undefined || value === null ? '' : `<${name}>${value}</${name}>`)

const s3Xml = (body) => `<?xml version="1.0" encoding="UTF-8"?>${body}`
const result = (name, inner) => s3Xml(`<${name} xmlns="${S3_XMLNS}">${inner}</${name}>`)

const iso = (date) => (date ? new Date(date).toISOString().replace(/\.\d{3}Z$/, 'Z') : undefined)

const encodeKey = (key, encoding) => (encoding === 'url' ? util.encodeKey(key) : key)

const createS3Server = (context, deps = {}) => {
    const {
        objects, buckets, repo, audit, events, config, logger, lifecycle, tiering, replication,
    } = context
    const { auth } = deps
    if (!auth) throw new Error('createS3Server requires the auth module')

    const region = () => config.servers.s3.region || 'us-east-1'
    const virtualHostDomain = config.servers.s3.domain || ''

    // ------------------------------------------------------------------
    // Addressing
    // ------------------------------------------------------------------
    const bucketFromHost = (req) => {
        if (!virtualHostDomain) return null
        const host = String(req.headers.host || '').split(':')[0].toLowerCase()
        const domain = virtualHostDomain.toLowerCase()
        if (host === domain) return null
        if (host.endsWith(`.${domain}`)) return host.slice(0, -(domain.length + 1)).split('.')[0]

        return null
    }

    const parseTarget = (req) => {
        const raw = util.decodeURIComponentSafe(req.ddrive?.s3Path || req.url.split('?')[0])
        const parts = raw.split('/').filter((p) => p.length > 0)
        const hostBucket = bucketFromHost(req)
        const bucket = hostBucket || (parts.length ? parts[0] : null)
        const key = hostBucket ? parts.join('/') : parts.slice(1).join('/')

        return { bucket, key, raw }
    }

    const queryValue = (req, name) => {
        const value = req.query ? req.query[name] : undefined
        if (value === undefined || value === null) return undefined

        return String(value)
    }
    const hasQuery = (req, name) => {
        const value = req.query ? req.query[name] : undefined
        if (value === undefined || value === null) return false
        // `?uploads` (no value) is a real S3 subresource
        return value === '' || value === true || value === 'true' || typeof value === 'string'
    }
    const queryText = (value) => (value === '' || value === true || value === undefined ? undefined : String(value))

    // ------------------------------------------------------------------
    // Responses
    // ------------------------------------------------------------------
    const commonHeaders = (req, reply) => {
        reply.header('x-amz-request-id', req.id)
        reply.header('x-amz-id-2', Buffer.from(`ddrive:${config.node.region}`).toString('base64'))
        reply.header('server', 'ddrive')
    }

    const sendError = (req, reply, err) => {
        const statusCode = err.statusCode || 500
        const code = err.code && typeof err.code === 'string' && /^[A-Za-z]/.test(err.code) ? err.code : 'InternalError'
        const message = statusCode >= 500 && err.expose === false ? 'We encountered an internal error. Please try again.' : (err.message || code)
        const resource = req.ddrive?.s3Path || req.url
        const body = s3Xml(`<Error><Code>${escape(code)}</Code><Message>${escape(message)}</Message>${el('Resource', resource)}${el('RequestId', req.id)}${el('HostId', 'ddrive')}</Error>`)
        commonHeaders(req, reply)
        // S3 answers a GET/HEAD of a delete-marked key with 404 *plus* this
        // header, so clients can tell "missing" from "newer than the marker"
        if (err.detail?.deleteMarker) {
            reply.header('x-amz-delete-marker', 'true')
            if (err.detail.versionId) reply.header('x-amz-version-id', err.detail.versionId)
        }
        if (req.method === 'HEAD') {
            reply.code(statusCode)

            return reply.send('')
        }
        reply.code(statusCode).header('content-type', 'application/xml; charset=utf-8')

        return reply.send(body)
    }

    const send = (req, reply, body, { statusCode = 200, headers = {} } = {}) => {
        commonHeaders(req, reply)
        Object.entries(headers).forEach(([k, v]) => { if (v !== undefined && v !== null) reply.header(k, v) })
        reply.code(statusCode).header('content-type', 'application/xml; charset=utf-8')

        return reply.send(body)
    }

    // ------------------------------------------------------------------
    // Owners / ACLs
    // ------------------------------------------------------------------
    const ownerXml = '<Owner><ID>ddrive</ID><DisplayName>ddrive</DisplayName></Owner>'
    const aclXml = () => s3Xml('<AccessControlPolicy>' + ownerXml + '<AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>ddrive</ID><DisplayName>ddrive</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>')

    // ------------------------------------------------------------------
    // Listings
    // ------------------------------------------------------------------
    const listBucket = async (req, reply, bucket) => {
        const v2 = hasQuery(req, 'list-type') && queryValue(req, 'list-type') === '2'
        const prefix = queryValue(req, 'prefix') || ''
        const delimiter = queryValue(req, 'delimiter') || ''
        const encoding = queryValue(req, 'encoding-type')
        const maxKeys = Math.min(Math.max(Number(queryValue(req, 'max-keys') || 1000) || 1000, 0), 1000)
        const marker = v2
            ? (queryValue(req, 'continuation-token') ? util.decodeContinuation(queryValue(req, 'continuation-token')) : (queryValue(req, 'start-after') || ''))
            : (queryValue(req, 'marker') || '')
        const listed = await objects.list({
            bucket, prefix, delimiter, maxKeys, startAfter: marker,
        })
        const commonPrefixes = listed.commonPrefixes || []
        const contents = listed.contents || []
        const truncated = !!(listed.isTruncated && (contents.length || commonPrefixes.length))
        const nextToken = truncated && contents.length ? util.encodeContinuation(contents[contents.length - 1].path) : null
        const rows = contents.map((node) => [
            '<Contents>',
            el('Key', encodeKey(node.path, encoding)),
            el('LastModified', iso(node.updatedAt || node.createdAt)),
            elRaw('ETag', `&quot;${escape(node.etag || '')}&quot;`),
            el('Size', Number(node.size || 0)),
            el('StorageClass', node.storageClass || 'STANDARD'),
            ownerXml,
            '</Contents>',
        ].join(''))

        if (v2) {
            return send(req, reply, result('ListBucketResult', [
                el('Name', bucket.name),
                el('Prefix', encodeKey(prefix, encoding)),
                el('Delimiter', delimiter),
                el('MaxKeys', maxKeys),
                el('KeyCount', contents.length + commonPrefixes.length),
                el('IsTruncated', truncated),
                nextToken ? el('NextContinuationToken', nextToken) : '',
                el('EncodingType', encoding),
                rows,
                commonPrefixes.map((p) => `<CommonPrefixes>${el('Prefix', encodeKey(p, encoding))}</CommonPrefixes>`).join(''),
            ].join('')))
        }

        const nextMarker = truncated && contents.length ? contents[contents.length - 1].path : undefined

        return send(req, reply, result('ListBucketResult', [
            el('Name', bucket.name),
            el('Prefix', encodeKey(prefix, encoding)),
            el('Marker', encodeKey(marker, encoding)),
            nextMarker ? el('NextMarker', encodeKey(nextMarker, encoding)) : '',
            el('Delimiter', delimiter),
            el('MaxKeys', maxKeys),
            el('IsTruncated', truncated),
            el('EncodingType', encoding),
            rows,
            commonPrefixes.map((p) => `<CommonPrefixes>${el('Prefix', encodeKey(p, encoding))}</CommonPrefixes>`).join(''),
        ].join('')))
    }

    const listVersions = async (req, reply, bucket) => {
        const prefix = queryValue(req, 'prefix') || ''
        const delimiter = queryValue(req, 'delimiter') || ''
        const encoding = queryValue(req, 'encoding-type')
        const maxKeys = Math.min(Number(queryValue(req, 'max-keys') || 1000) || 1000, 1000)
        const keyMarker = queryValue(req, 'key-marker') || ''
        const versionIdMarker = queryValue(req, 'version-id-marker') || ''
        const listed = await objects.listVersions(bucket, {
            prefix, delimiter, maxKeys, keyMarker, versionIdMarker, encodingUrl: encoding === 'url',
        })
        const rows = (listed.versions || []).map((v) => (v.isDeleteMarker
            ? `<DeleteMarker>${el('Key', encodeKey(v.path, encoding))}${el('VersionId', v.id)}${el('IsLatest', !!v.isLatest)}${el('LastModified', iso(v.createdAt))}${ownerXml}</DeleteMarker>`
            : `<Version>${el('Key', encodeKey(v.path, encoding))}${el('VersionId', v.id)}${el('IsLatest', !!v.isLatest)}${el('LastModified', iso(v.createdAt))}${elRaw('ETag', `&quot;${escape(v.etag || '')}&quot;`)}${el('Size', Number(v.size || 0))}${el('StorageClass', v.storageClass || 'STANDARD')}${ownerXml}</Version>`))

        return send(req, reply, result('ListVersionsResult', [
            el('Name', bucket.name),
            el('Prefix', encodeKey(prefix, encoding)),
            el('KeyMarker', keyMarker),
            el('VersionIdMarker', versionIdMarker),
            el('MaxKeys', maxKeys),
            el('Delimiter', delimiter),
            el('IsTruncated', !!listed.isTruncated),
            listed.nextKeyMarker ? el('NextKeyMarker', encodeKey(listed.nextKeyMarker, encoding)) : '',
            listed.nextVersionIdMarker ? el('NextVersionIdMarker', listed.nextVersionIdMarker) : '',
            el('EncodingType', encoding),
            rows.join(''),
            (listed.commonPrefixes || []).map((p) => `<CommonPrefixes>${el('Prefix', encodeKey(p, encoding))}</CommonPrefixes>`).join(''),
        ].join('')))
    }

    const listMultipartUploads = async (req, reply, bucket) => {
        const uploads = await objects.listMultipartUploads(bucket)
        const prefix = queryValue(req, 'prefix') || ''
        const filtered = prefix ? uploads.filter((u) => String(u.path).startsWith(prefix)) : uploads

        return send(req, reply, result('ListMultipartUploadsResult', [
            el('Bucket', bucket.name),
            el('KeyMarker', ''),
            el('UploadIdMarker', ''),
            el('MaxUploads', 1000),
            el('IsTruncated', false),
            filtered.map((u) => [
                '<Upload>',
                el('Key', u.path),
                el('UploadId', u.id),
                `<Initiator><ID>ddrive</ID><DisplayName>ddrive</DisplayName></Initiator>`,
                ownerXml,
                el('StorageClass', u.storageClass || 'STANDARD'),
                el('Initiated', iso(u.createdAt)),
                '</Upload>',
            ].join('')).join(''),
        ].join('')))
    }

    // ------------------------------------------------------------------
    // Objects
    // ------------------------------------------------------------------
    const headOrGet = async (req, reply, bucket, key) => {
        const versionId = queryValue(req, 'versionId')
        const { node, version } = await objects.getVersion(bucket, key, versionId)
        const isHead = req.method === 'HEAD'
        // conditional headers
        const etag = `"${node.etag || ''}"`
        const lastModified = new Date(node.updatedAt || node.createdAt)
        if (req.headers['if-match'] && !String(req.headers['if-match']).split(',').map((s) => s.trim()).includes(etag) && req.headers['if-match'] !== '*') {
            throw errors.preconditionFailed()
        }
        if (req.headers['if-none-match'] && (req.headers['if-none-match'] === '*' || String(req.headers['if-none-match']).includes(node.etag))) {
            const err = errors.notModified ? errors.notModified() : new StorageError('NotModified', 'Not modified', { statusCode: 304 })
            err.statusCode = 304
            throw err
        }
        if (req.headers['if-modified-since'] && lastModified <= new Date(req.headers['if-modified-since'])) {
            const err = new StorageError('NotModified', 'Not modified', { statusCode: 304 })
            throw err
        }
        const range = !isHead && req.headers.range ? util.parseRange(req.headers.range, Number(version.size)) : null
        const streamed = isHead ? null : await objects.stream(version, range)
        commonHeaders(req, reply)
        reply.header('accept-ranges', 'bytes')
        reply.header('last-modified', lastModified.toUTCString())
        reply.header('etag', etag)
        reply.header('content-type', version.contentType || node.contentType || util.contentTypeOf(node.name))
        reply.header('content-length', String(range ? range.length : Number(version.size || 0)))
        if (version.id) reply.header('x-amz-version-id', version.id)
        if (range) reply.header('content-range', `bytes ${range.start}-${range.end}/${version.size}`)
        if (node.metadata && typeof node.metadata === 'object') {
            Object.entries(node.metadata).forEach(([k, v]) => {
                if (/^[a-zA-Z0-9!#$%&'*+.^_`|~-]+$/.test(k) && v !== null && typeof v !== 'object') reply.header(`x-amz-meta-${k.toLowerCase()}`, String(v))
            })
        }
        if (node.tags && Object.keys(node.tags).length) {
            reply.header('x-amz-tagging-count', String(Object.keys(node.tags).length))
        }
        if (node.storageClass && node.storageClass !== 'STANDARD') reply.header('x-amz-storage-class', node.storageClass)
        if (node.replicationStatus && node.replicationStatus !== 'none') reply.header('x-amz-replication-status', node.replicationStatus === 'replicated' ? 'COMPLETED' : 'PENDING')
        const responseType = queryValue(req, 'response-content-type')
        if (responseType) reply.header('content-type', responseType)
        if (queryValue(req, 'response-content-disposition')) reply.header('content-disposition', queryValue(req, 'response-content-disposition'))
        if (queryValue(req, 'response-cache-control')) reply.header('cache-control', queryValue(req, 'response-cache-control'))
        reply.code(range ? 206 : 200)
        if (isHead) return reply.send('')
        await objects.recordAccess(version, range ? range.length : Number(version.size || 0))

        return reply.send(streamed.stream)
    }

    /**
     * The request body as the object payload:
     *  - `aws-chunked` framing is decoded (and chunk signatures checked),
     *  - `x-amz-content-sha256` is verified for in-memory sized uploads.
     */
    const payloadStream = (req, { verify = true } = {}) => {
        const hash = String(req.headers['x-amz-content-sha256'] || '')
        const signed = req.ddrive?.sigv4 || null
        if (sigv4.isChunked(req.headers)) {
            const stream = sigv4.decodeChunkedStream(req.raw, {
                signingKey: signed?.signingKey,
                amzDate: signed?.amzDate,
                dateStamp: signed?.dateStamp,
                region: signed?.region,
                service: signed?.service,
                verify: verify && /^STREAMING-AWS4/.test(hash) && !!signed?.signingKey,
                maxBytes: 0,
            })

            return { stream, verifier: null }
        }
        const limit = Number(config.storage.verifyLimitBytes || 0)
        const declared = Number(req.headers['content-length'] || 0)
        const verifier = verify && limit > 0 && declared > 0 && declared <= limit ? sigv4.payloadVerifier(hash) : null

        return { stream: verifier ? req.raw.pipe(verifier.stream) : req.raw, verifier }
    }

    const putObject = async (req, reply, bucket, key) => {
        const copySource = req.headers['x-amz-copy-source']
        if (copySource) return copyObject(req, reply, bucket, key, copySource)
        const metadataDirective = (req.headers['x-amz-metadata-directive'] || 'COPY').toUpperCase()
        void metadataDirective
        const metadata = {}
        Object.entries(req.headers).forEach(([header, value]) => {
            const match = /^x-amz-meta-(.+)$/i.exec(header)
            if (match) metadata[match[1]] = String(value)
        })
        const tags = {}
        if (req.headers['x-amz-tagging']) {
            new URLSearchParams(String(req.headers['x-amz-tagging'])).forEach((value, tagKey) => { tags[tagKey] = value })
        }
        const conditions = {}
        if (req.headers['if-none-match'] === '*') conditions.ifNoneMatch = '*'
        if (req.headers['if-match']) conditions.ifMatch = req.headers['if-match']
        const storageClass = req.headers['x-amz-storage-class']
        const { stream, verifier } = payloadStream(req)
        const written = await objects.putObject({
            bucket,
            path: key,
            stream,
            contentType: req.headers['content-type'],
            metadata: Object.keys(metadata).length ? metadata : undefined,
            tags: Object.keys(tags).length ? tags : undefined,
            storageClass: storageClass || undefined,
            contentMd5: req.headers['content-md5'],
            retentionMode: req.headers['x-amz-object-lock-mode'],
            retainUntil: req.headers['x-amz-object-lock-retain-until-date'],
            legalHold: req.headers['x-amz-object-lock-legal-hold'] ? req.headers['x-amz-object-lock-legal-hold'] === 'ON' : undefined,
            actor: actorOf(req),
            conditions,
        })
        if (verifier && !verifier.verify()) {
            await objects.deleteObject({
                bucket, path: key, permanent: true, versionId: written.versionId, actor: actorOf(req),
            }).catch(() => {})

            throw new StorageError('XAmzContentSHA256Mismatch', 'The provided x-amz-content-sha256 does not match what was computed', { statusCode: 400 })
        }
        if (events) events.emit('OBJECT_CREATED', { bucket, key, size: written.size }).catch(() => {})
        await auditFor(req, 's3.PutObject', bucket, key, {
            size: written.size, storageClass: storageClass || 'STANDARD', versionId: written.versionId,
        })
        send(req, reply, '', {
            headers: {
                etag: `"${written.etag}"`,
                'x-amz-version-id': written.versionId,
                'x-amz-storage-class': storageClass,
            },
        })

        return reply.send('')
    }

    const copyObject = async (req, reply, bucket, key, copySource) => {
        const decoded = util.decodeURIComponentSafe(String(copySource))
        const source = parseCopySource(decoded)
        const sourceVersion = source.query.versionId
        const directive = (req.headers['x-amz-metadata-directive'] || 'COPY').toUpperCase()
        const tagDirective = (req.headers['x-amz-tagging-directive'] || 'COPY').toUpperCase()
        const metadata = {}
        if (directive === 'REPLACE') {
            Object.entries(req.headers).forEach(([header, value]) => {
                const match = /^x-amz-meta-(.+)$/i.exec(header)
                if (match) metadata[match[1]] = String(value)
            })
        }
        const tags = {}
        if (tagDirective === 'REPLACE' && req.headers['x-amz-tagging']) {
            new URLSearchParams(String(req.headers['x-amz-tagging'])).forEach((value, tagKey) => { tags[tagKey] = value })
        }
        const sourceBucket = source.bucket === bucket.name ? bucket : await buckets.get(source.bucket)
        const copied = await objects.copy(
            { bucket: sourceBucket, path: source.key, versionId: sourceVersion },
            { bucket, path: key },
            {
                metadata: directive === 'REPLACE' ? metadata : undefined,
                metadataDirective: directive,
                tagsDirective: tagDirective,
                tags: tagDirective === 'REPLACE' ? tags : undefined,
                storageClass: req.headers['x-amz-storage-class'] || undefined,
                actor: actorOf(req),
            },
        )
        await auditFor(req, 's3.CopyObject', bucket, key, { source: `${source.bucket}/${source.key}`, versionId: copied.versionId })
        const body = result('CopyObjectResult', `${elRaw('ETag', `&quot;${escape(copied.etag || '')}&quot;`)}${el('LastModified', iso(new Date()))}`)

        return send(req, reply, body, { headers: { 'x-amz-version-id': copied.versionId } })
    }

    const parseCopySource = (value) => {
        const [pathPart, queryPart] = String(value).split('?')
        const parts = pathPart.replace(/^\/+/, '').split('/')
        const bucket = parts.shift()
        const query = new URLSearchParams(queryPart || '')

        return { bucket, key: parts.join('/'), query: { versionId: query.get('versionId') || undefined } }
    }

    const deleteObject = async (req, reply, bucket, key) => {
        const versionId = queryValue(req, 'versionId')
        const result_ = await objects.deleteObject({
            bucket,
            path: key,
            versionId,
            permanent: !!versionId || bucket.versioning !== 'enabled',
            bypassGovernance: String(req.headers['x-amz-bypass-governance-retention'] || '').toUpperCase() === 'TRUE',
            actor: actorOf(req),
        })
        await auditFor(req, 's3.DeleteObject', bucket, key, { versionId, deleteMarker: !!result_.deleteMarker })
        send(req, reply, '', {
            statusCode: 204,
            headers: {
                'x-amz-version-id': result_.versionId || versionId || 'null',
                'x-amz-delete-marker': result_.deleteMarker ? 'true' : undefined,
            },
        })

        return reply.send('')
    }

    const deleteObjects = async (req, reply, bucket) => {
        const body = await util.bodyText(req)
        const parsed = xml.parseXml(body)
        const root = xml.node(parsed, 'Delete') || {}
        const quiet = String(xml.text(xml.node(root, 'Quiet')) || '').toLowerCase() === 'true'
        const wanted = xml.nodes(root, 'Object').slice(0, 1000)
        const deleted = []
        const errors_ = []
        for (const item of wanted) {
            const key = xml.text(xml.node(item, 'Key'))
            const versionId = xml.text(xml.node(item, 'VersionId'))
            // eslint-disable-next-line no-await-in-loop
            try {
                // eslint-disable-next-line no-await-in-loop
                const removed = await objects.deleteObject({
                    bucket, path: key, versionId, permanent: !!versionId, actor: actorOf(req),
                })
                deleted.push(`<Deleted>${el('Key', key)}${versionId ? el('VersionId', versionId) : ''}${removed.deleteMarker ? el('DeleteMarker', 'true') + el('DeleteMarkerVersionId', removed.versionId) : ''}</Deleted>`)
            } catch (err) {
                errors_.push(`<Error>${el('Key', key)}${el('VersionId', versionId)}${el('Code', err.code || 'InternalError')}${el('Message', err.message)}</Error>`)
            }
        }

        return send(req, reply, result('DeleteResult', [
            quiet ? '' : deleted.join(''),
            errors_.join(''),
        ].join('')))
    }

    // ------------------------------------------------------------------
    // Multipart
    // ------------------------------------------------------------------
    const initiateMultipart = async (req, reply, bucket, key) => {
        const metadata = {}
        Object.entries(req.headers).forEach(([header, value]) => {
            const match = /^x-amz-meta-(.+)$/i.exec(header)
            if (match) metadata[match[1]] = String(value)
        })
        const upload = await objects.initiateMultipart({
            bucket,
            path: key,
            contentType: req.headers['content-type'],
            metadata: Object.keys(metadata).length ? metadata : undefined,
            storageClass: req.headers['x-amz-storage-class'] || undefined,
            actor: actorOf(req),
        })

        return send(req, reply, result('InitiateMultipartUploadResult', `${el('Bucket', bucket.name)}${el('Key', key)}${el('UploadId', upload.id)}`))
    }

    const uploadPart = async (req, reply, bucket, key, partNumber, uploadId) => {
        if (!partNumber || Number(partNumber) < 1 || Number(partNumber) > 10000) throw errors.invalidArgument('Part number must be between 1 and 10000')
        const copySource = req.headers['x-amz-copy-source']
        if (copySource) {
            const source = parseCopySource(util.decodeURIComponentSafe(copySource))
            const sourceBucket = source.bucket === bucket.name ? bucket : await buckets.get(source.bucket)
            const { version } = await objects.getVersion(sourceBucket, source.key, source.query.versionId)
            const range = req.headers['x-amz-copy-source-range']
                ? util.parseRange(String(req.headers['x-amz-copy-source-range']).replace('bytes=', ''), Number(version.size))
                : null
            const streamed = await objects.stream(version, range)
            const part = await objects.uploadPart(bucket, uploadId, Number(partNumber), streamed.stream)
            await auditFor(req, 's3.UploadPartCopy', bucket, key, { uploadId, partNumber: Number(partNumber) })

            return send(req, reply, result('CopyPartResult', `${elRaw('ETag', `&quot;${escape(part.etag)}&quot;`)}${el('LastModified', iso(new Date()))}`), { headers: { etag: `"${part.etag}"` } })
        }
        const { stream: partStream } = payloadStream(req, { verify: false })
        const part = await objects.uploadPart(bucket, uploadId, Number(partNumber), partStream)

        return send(req, reply, '', { headers: { etag: `"${part.etag}"` } })
    }

    const completeMultipart = async (req, reply, bucket, key, uploadId) => {
        const parsed = xml.parseXml(await util.bodyText(req))
        const root = xml.node(parsed, 'CompleteMultipartUpload') || {}
        const parts = xml.nodes(root, 'Part').map((item) => ({
            partNumber: Number(xml.text(xml.node(item, 'PartNumber'))),
            etag: String(xml.text(xml.node(item, 'ETag')) || '').replace(/"/g, ''),
        }))
        if (!parts.length) throw errors.invalidRequest('You must specify at least one part')
        const completed = await objects.completeMultipart(bucket, uploadId, parts, actorOf(req))
        await auditFor(req, 's3.CompleteMultipartUpload', bucket, key, { uploadId, size: completed.size })
        const body = result('CompleteMultipartUploadResult', `${el('Location', `${config.servers.baseUrl || ''}${config.servers.s3.path}/${bucket.name}/${key}`)}${el('Bucket', bucket.name)}${el('Key', key)}${elRaw('ETag', `&quot;${escape(completed.etag || '')}&quot;`)}`)

        return send(req, reply, body, { headers: { 'x-amz-version-id': completed.versionId } })
    }

    const listParts = async (req, reply, bucket, key, uploadId) => {
        const listed = await objects.listParts(bucket, uploadId)
        const body = result('ListPartsResult', [
            el('Bucket', bucket.name),
            el('Key', key),
            el('UploadId', uploadId),
            el('StorageClass', 'STANDARD'),
            el('PartNumberMarker', 0),
            el('NextPartNumberMarker', listed.parts.length),
            el('MaxParts', 1000),
            el('IsTruncated', false),
            listed.parts.map((p) => `<Part>${el('PartNumber', p.partNumber)}${el('LastModified', iso(p.createdAt))}${elRaw('ETag', `&quot;${escape(p.etag)}&quot;`)}${el('Size', p.size)}</Part>`).join(''),
        ].join(''))

        return send(req, reply, body)
    }

    // ------------------------------------------------------------------
    // Bucket configuration
    // ------------------------------------------------------------------
    const bucketSubresource = async (req, reply, bucket) => {
        const isPut = req.method === 'PUT'
        const isDelete = req.method === 'DELETE'
        if (hasQuery(req, 'versioning')) {
            if (isPut) {
                const body = xml.parseXml(await util.bodyText(req))
                const status = xml.text(xml.node(xml.node(body, 'VersioningConfiguration') || {}, 'Status'))
                if (!status || !['Enabled', 'Suspended'].includes(status)) throw errors.invalidArgument('Invalid versioning status')
                await buckets.update(bucket.name, { versioning: status === 'Enabled' ? 'enabled' : 'suspended' })

                return send(req, reply, '')
            }

            return send(req, reply, result('VersioningConfiguration', bucket.versioning === 'enabled' ? '<Status>Enabled</Status>' : (bucket.versioning === 'suspended' ? '<Status>Suspended</Status>' : '')))
        }
        if (hasQuery(req, 'policy')) {
            if (isPut) {
                const body = await util.bodyText(req)
                const document = JSON.parse(body)
                await buckets.setPolicy(bucket.name, document, actorOf(req))
                await auditFor(req, 's3.PutBucketPolicy', bucket, null, {})

                return send(req, reply, '')
            }
            if (isDelete) {
                await buckets.setPolicy(bucket.name, null, actorOf(req))
                send(req, reply, '', { statusCode: 204 })

                return reply.send('')
            }
            const policy = await buckets.getPolicy(bucket.name)

            return send(req, reply, s3Xml(JSON.stringify(policy || {})))
        }
        if (hasQuery(req, 'object-lock')) {
            if (isPut) {
                const body = xml.parseXml(await util.bodyText(req))
                const config = xml.node(body, 'ObjectLockConfiguration') || {}
                const rule = xml.node(config, 'Rule') || {}
                const retention = xml.node(rule, 'DefaultRetention') || {}
                const mode = xml.text(xml.node(retention, 'Mode'))
                const days = xml.text(xml.node(retention, 'Days'))
                const years = xml.text(xml.node(retention, 'Years'))
                await buckets.setObjectLock(bucket.name, {
                    enabled: String(xml.text(xml.node(config, 'ObjectLockEnabled')) || '').toUpperCase() !== 'DISABLED',
                    mode,
                    days: days ? Number(days) : (years ? Number(years) * 365 : undefined),
                })

                return send(req, reply, '')
            }
            const lock = await buckets.getObjectLock(bucket.name)
            if (!lock || !lock.enabled) throw new StorageError('ObjectLockConfigurationNotFoundError', 'Object Lock configuration does not exist for this bucket')
            const retention = lock.mode
                ? `<DefaultRetention>${el('Mode', lock.mode)}${el('Days', lock.days)}</DefaultRetention>`
                : ''

            return send(req, reply, result('ObjectLockConfiguration', `<ObjectLockEnabled>Enabled</ObjectLockEnabled>${retention ? `<Rule>${retention}</Rule>` : ''}`))
        }
        if (hasQuery(req, 'tagging')) {
            const tagSet = (tags) => Object.entries(tags || {}).map(([k, v]) => `<Tag>${el('Key', k)}${el('Value', v)}</Tag>`).join('')
            if (isPut) {
                const body = xml.parseXml(await util.bodyText(req))
                const tagSetNode = xml.node(xml.node(body, 'Tagging') || {}, 'TagSet') || {}
                const tags = {}
                xml.nodes(tagSetNode, 'Tag').forEach((tag) => { tags[xml.text(xml.node(tag, 'Key'))] = xml.text(xml.node(tag, 'Value')) })
                await buckets.update(bucket.name, { tags })

                return send(req, reply, '')
            }

            return send(req, reply, result('Tagging', `<TagSet>${tagSet(bucket.tags)}</TagSet>`))
        }
        if (hasQuery(req, 'lifecycle')) {
            if (isPut) {
                const body = xml.parseXml(await util.bodyText(req))
                const configuration = xml.node(body, 'LifecycleConfiguration') || {}
                const rules = xml.nodes(configuration, 'Rule')
                const existing = await lifecycle.listRules(bucket)
                for (const rule of existing) {
                    // eslint-disable-next-line no-await-in-loop
                    await lifecycle.deleteRule(rule.id)
                }
                for (const rule of rules) {
                    // eslint-disable-next-line no-await-in-loop
                    await lifecycle.createRule(bucket, lifecycleRuleInput(rule), actorOf(req))
                }

                return send(req, reply, '')
            }
            if (isDelete) {
                const existing = await lifecycle.listRules(bucket)
                for (const rule of existing) {
                    // eslint-disable-next-line no-await-in-loop
                    await lifecycle.deleteRule(rule.id)
                }
                send(req, reply, '', { statusCode: 204 })

                return reply.send('')
            }
            const rules = await lifecycle.listRules(bucket)
            if (!rules.length) throw new StorageError('NoSuchLifecycleConfiguration', 'The lifecycle configuration does not exist')

            const body = rules.map((rule) => [
                '<Rule>',
                el('ID', rule.name),
                el('Status', rule.status || 'Enabled'),
                rule.prefix ? `<Filter><Prefix>${escape(rule.prefix)}</Prefix></Filter>` : '',
                (rule.transitions || []).map((t) => `<Transition>${el('Days', t.days)}${el('StorageClass', t.storageClass)}</Transition>`).join(''),
                rule.expirationDays ? `<Expiration>${el('Days', rule.expirationDays)}</Expiration>` : '',
                rule.noncurrentVersionExpirationDays ? `<NoncurrentVersionExpiration>${el('NoncurrentDays', rule.noncurrentVersionExpirationDays)}</NoncurrentVersionExpiration>` : '',
                rule.abortIncompleteMultipartDays ? `<AbortIncompleteMultipartUpload>${el('DaysAfterInitiation', rule.abortIncompleteMultipartDays)}</AbortIncompleteMultipartUpload>` : '',
                '</Rule>',
            ].join('')).join('')

            return send(req, reply, result('LifecycleConfiguration', body))
        }
        if (hasQuery(req, 'replication')) {
            if (isPut) {
                const body = xml.parseXml(await util.bodyText(req))
                const configuration = xml.node(body, 'ReplicationConfiguration') || {}
                const role = xml.text(xml.node(configuration, 'Role'))
                const rules = xml.nodes(configuration, 'Rule')
                const created = []
                for (const rule of rules) {
                    const destination = xml.node(rule, 'Destination') || {}
                    const name = xml.text(xml.node(rule, 'ID')) || `rule-${Date.now()}`
                    // eslint-disable-next-line no-await-in-loop
                    const peer = await replication.createPeer({
                        name,
                        endpoint: xml.text(xml.node(destination, 'Endpoint')) || xml.text(xml.node(destination, 'Bucket')) || '',
                        bucket: xml.text(xml.node(destination, 'Bucket')) || bucket.name,
                        region: xml.text(xml.node(destination, 'StorageClass')) || null,
                        accessKeyId: xml.text(xml.node(destination, 'AccessKeyId')) || 'ddrive',
                        secret: xml.text(xml.node(destination, 'SecretAccessKey')) || 'ddrive',
                        prefix: xml.text(xml.node(xml.node(rule, 'Filter') || {}, 'Prefix')) || null,
                        direction: 'outbound',
                        mode: 's3',
                    })
                    created.push(peer.name)
                }
                void role

                return send(req, reply, result('ReplicationConfiguration', `${el('Role', 'arn:aws:iam::ddrive:role/replication')}${created.map((name) => `<Rule>${el('ID', name)}${el('Status', 'Enabled')}<Destination>${el('Bucket', bucket.name)}</Destination></Rule>`).join('')}`))
            }
            if (isDelete) {
                send(req, reply, '', { statusCode: 204 })

                return reply.send('')
            }
            const peers = await replication.listPeers()
            const rules = peers.filter((peer) => peer.direction !== 'inbound').map((peer) => `<Rule>${el('ID', peer.name)}${el('Status', peer.status === 'enabled' ? 'Enabled' : 'Disabled')}<Destination>${el('Bucket', peer.bucket || bucket.name)}${peer.endpoint ? el('Endpoint', peer.endpoint) : ''}</Destination></Rule>`).join('')

            return send(req, reply, result('ReplicationConfiguration', `${el('Role', 'arn:aws:iam::ddrive:role/replication')}${rules}`))
        }
        if (hasQuery(req, 'location')) return send(req, reply, result('LocationConstraint', bucket.region === 'us-east-1' ? '' : el('', bucket.region).replace(/^<(\/?)><\/\1>$/, '') || escape(bucket.region)))
        if (hasQuery(req, 'acl')) return send(req, reply, aclXml())
        if (hasQuery(req, 'cors')) return send(req, reply, result('CORSConfiguration', (bucket.cors || []).map((r) => `<CORSRule>${(r.allowedOrigins || ['*']).map((o) => el('AllowedOrigin', o)).join('')}${(r.allowedMethods || ['GET']).map((m) => el('AllowedMethod', m)).join('')}${(r.allowedHeaders || []).map((h) => el('AllowedHeader', h)).join('')}${el('MaxAgeSeconds', r.maxAgeSeconds || 3000)}</CORSRule>`).join('')))
        if (hasQuery(req, 'encryption')) return send(req, reply, result('ServerSideEncryptionConfiguration', '<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>'))
        if (hasQuery(req, 'logging')) return send(req, reply, result('BucketLoggingStatus', ''))
        if (hasQuery(req, 'notification')) return send(req, reply, result('NotificationConfiguration', ''))
        if (hasQuery(req, 'accelerate')) return send(req, reply, result('AccelerateConfiguration', ''))
        if (hasQuery(req, 'website')) return send(req, reply, result('WebsiteConfiguration', ''))

        throw new StorageError('NoSuchSubresource', `The ${req.url.split('?')[1]} subresource is not supported`)
    }

    const lifecycleRuleInput = (rule) => {
        const filter = xml.node(rule, 'Filter') || {}
        const transitions = xml.nodes(rule, 'Transition').map((t) => ({
            days: Number(xml.text(xml.node(t, 'Days')) || 0),
            storageClass: xml.text(xml.node(t, 'StorageClass')),
        }))
        const expiration = xml.node(rule, 'Expiration') || {}
        const noncurrent = xml.node(rule, 'NoncurrentVersionExpiration') || {}
        const abort = xml.node(rule, 'AbortIncompleteMultipartUpload') || {}
        const status = xml.text(xml.node(rule, 'Status')) || 'Enabled'

        return {
            name: xml.text(xml.node(rule, 'ID')) || `rule-${util.randomHex(4)}`,
            status,
            prefix: xml.text(xml.node(filter, 'Prefix')) ?? xml.text(xml.node(rule, 'Prefix')) ?? null,
            transitions,
            expirationDays: xml.text(xml.node(expiration, 'Days')) ? Number(xml.text(xml.node(expiration, 'Days'))) : null,
            noncurrentVersionExpirationDays: xml.text(xml.node(noncurrent, 'NoncurrentDays')) ? Number(xml.text(xml.node(noncurrent, 'NoncurrentDays'))) : null,
            abortIncompleteMultipartDays: xml.text(xml.node(abort, 'DaysAfterInitiation')) ? Number(xml.text(xml.node(abort, 'DaysAfterInitiation'))) : null,
        }
    }

    // ------------------------------------------------------------------
    // Object subresources
    // ------------------------------------------------------------------
    const objectSubresource = async (req, reply, bucket, key) => {
        const versionId = queryValue(req, 'versionId')
        if (hasQuery(req, 'tagging')) {
            if (req.method === 'PUT') {
                const body = xml.parseXml(await util.bodyText(req))
                const tagSetNode = xml.node(xml.node(body, 'Tagging') || {}, 'TagSet') || {}
                const tags = {}
                xml.nodes(tagSetNode, 'Tag').forEach((tag) => { tags[xml.text(xml.node(tag, 'Key'))] = xml.text(xml.node(tag, 'Value')) })
                const saved = await objects.setTags(bucket, key, tags, actorOf(req), versionId)
                await auditFor(req, 's3.PutObjectTagging', bucket, key, { tags: Object.keys(saved || {}) })

                return send(req, reply, '')
            }
            if (req.method === 'DELETE') {
                await objects.deleteTags(bucket, key, actorOf(req))
                send(req, reply, '', { statusCode: 204 })

                return reply.send('')
            }
            const tags = await objects.getTags(bucket, key)

            return send(req, reply, result('Tagging', `<TagSet>${Object.entries(tags || {}).map(([k, v]) => `<Tag>${el('Key', k)}${el('Value', v)}</Tag>`).join('')}</TagSet>`))
        }
        if (hasQuery(req, 'retention')) {
            if (req.method === 'PUT') {
                const body = xml.parseXml(await util.bodyText(req))
                const retention = xml.node(body, 'Retention') || {}
                const mode = xml.text(xml.node(retention, 'Mode'))
                const until = xml.text(xml.node(retention, 'RetainUntilDate'))
                await objects.setRetention(bucket, key, { mode, retainUntil: until ? new Date(until) : null }, actorOf(req), versionId)
                await auditFor(req, 's3.PutObjectRetention', bucket, key, { mode })

                return send(req, reply, '')
            }
            const retention = await objects.getRetention(bucket, key, versionId)
            if (!retention.mode || !retention.retainUntil) throw new StorageError('NoSuchObjectLockConfiguration', 'The specified object does not have a retention configuration')
            const body = result('Retention', `${el('Mode', retention.mode)}${el('RetainUntilDate', iso(retention.retainUntil))}`)

            return send(req, reply, body)
        }
        if (hasQuery(req, 'legal-hold')) {
            if (req.method === 'PUT') {
                const body = xml.parseXml(await util.bodyText(req))
                const hold = xml.node(body, 'LegalHold') || {}
                const status = String(xml.text(xml.node(hold, 'Status')) || '').toUpperCase()
                if (!['ON', 'OFF'].includes(status)) throw errors.invalidArgument('LegalHold status must be ON or OFF')
                await objects.setLegalHold(bucket, key, status === 'ON', actorOf(req))
                await auditFor(req, 's3.PutObjectLegalHold', bucket, key, { status })

                return send(req, reply, '')
            }
            const retention = await objects.getRetention(bucket, key, versionId)
            const body = result('LegalHold', el('Status', retention.legalHold ? 'ON' : 'OFF'))

            return send(req, reply, body)
        }
        if (hasQuery(req, 'attributes')) {
            const { node, version } = await objects.getVersion(bucket, key, versionId)
            const body = result('GetObjectAttributesResponse', [
                el('ETag', node.etag),
                el('ObjectSize', version.size),
                el('StorageClass', version.storageClass || 'STANDARD'),
                el('ObjectParts', ''),
            ].join(''))

            return send(req, reply, body, { headers: { 'last-modified': new Date(node.updatedAt || node.createdAt).toUTCString() } })
        }
        if (hasQuery(req, 'restore')) {
            const { version } = await objects.getVersion(bucket, key, versionId)
            if ((version.tier || 'HOT') === 'HOT') throw errors.invalidRequest('Object is already in the HOT tier')
            await tiering.transitionVersion(bucket, await objects.getNode(bucket.id, key), version, 'HOT', { reason: 'restore' })

            return send(req, reply, result('RestoreObjectResult', ''))
        }
        throw new StorageError('NoSuchSubresource', `The ?${req.url.split('?')[1]} subresource is not supported on objects`)
    }

    // ------------------------------------------------------------------
    // Auth helpers
    // ------------------------------------------------------------------
    const actorOf = (req) => ({
        id: req.ddrive?.principal?.id || null,
        name: req.ddrive?.principal?.name || 'anonymous',
        protocol: 's3',
        ip: req.ddrive?.ip,
        requestId: req.id,
    })

    const auditFor = async (req, action, bucket, key, detail) => {
        if (!audit) return
        await audit.record({
            action,
            actor: req.ddrive?.principal?.name || 'anonymous',
            actorId: req.ddrive?.principal?.id || null,
            actorType: req.ddrive?.principal?.type || 'anonymous',
            protocol: 's3',
            bucket: bucket ? bucket.name : null,
            objectKey: key || null,
            ip: req.ddrive?.ip,
            requestId: req.id,
            result: 'success',
            detail,
        }).catch((err) => logger.warn?.({ err }, 'audit record failed'))
    }

    // ------------------------------------------------------------------
    // Dispatch
    // ------------------------------------------------------------------
    const dispatch = async (req, reply, supplied) => {
        const { bucket: bucketName, key } = parseTarget(req)
        try {
            // S3 allows anonymous access, so a failed authentication is only
            // fatal when no anonymous policy grants the action.
            const principal = supplied || await auth.principalFor(req)
            req.ddrive.principal = principal
            // -------- service level
            if (!bucketName) {
                if (req.method !== 'GET') throw errors.methodNotAllowed(`${req.method} is not supported on the service endpoint`)
                await auth.authorize(req, principal, 's3:ListAllMyBuckets', {})
                const list = await buckets.list()
                const body = result('ListAllMyBucketsResult', `${ownerXml}<Buckets>${list.map((bucket) => `<Bucket>${el('Name', bucket.name)}${el('CreationDate', iso(bucket.createdAt))}</Bucket>`).join('')}</Buckets>`)

                return send(req, reply, body)
            }
            const bucketExists = await buckets.exists(bucketName).catch(() => false)
            if (!bucketExists) {
                if (req.method === 'PUT') {
                    await auth.authorize(req, principal, 's3:CreateBucket', { bucket: bucketName })
                    const bucket = await buckets.create(bucketName, {
                        region: region(),
                        ownerId: principal?.id || null,
                        createdBy: principal?.name || null,
                    })
                    await auditFor(req, 's3.CreateBucket', bucket, null, {})
                    const locationBody = region() === 'us-east-1' ? '' : el('LocationConstraint', region())

                    return send(req, reply, result('CreateBucketConfiguration', locationBody), { statusCode: 200, headers: { location: `/${bucketName}` } })
                }
                throw errors.noSuchBucket(bucketName)
            }
            const bucket = await buckets.get(bucketName)

            // -------- bucket level
            const subresource = ['versioning', 'policy', 'object-lock', 'tagging', 'lifecycle', 'replication', 'location', 'acl', 'cors', 'encryption', 'logging', 'notification', 'accelerate', 'website', 'uploads']
            const hasSubresource = subresource.some((name) => hasQuery(req, name))
            if (!key) {
                if (req.method === 'HEAD') {
                    await auth.authorize(req, principal, 's3:ListBucket', { bucket: bucketName })
                    commonHeaders(req, reply)
                    reply.header('x-amz-bucket-region', bucket.region || region())
                    reply.code(200)

                    return reply.send('')
                }
                if (req.method === 'DELETE') {
                    await auth.authorize(req, principal, 's3:DeleteBucket', { bucket: bucketName })
                    const force = String(queryValue(req, 'force') || '') === 'true'
                    await buckets.remove(bucketName, { force, actor: principal?.name })
                    await auditFor(req, 's3.DeleteBucket', bucket, null, { force })
                    send(req, reply, '', { statusCode: 204 })

                    return reply.send('')
                }
                if (req.method === 'POST' && hasQuery(req, 'delete')) {
                    await auth.authorize(req, principal, 's3:DeleteObject', { bucket: bucketName })

                    return deleteObjects(req, reply, bucket)
                }
                if (req.method === 'GET') {
                    if (hasQuery(req, 'uploads')) {
                        await auth.authorize(req, principal, 's3:ListBucketMultipartUploads', { bucket: bucketName })

                        return listMultipartUploads(req, reply, bucket)
                    }
                    if (hasQuery(req, 'versions')) {
                        await auth.authorize(req, principal, 's3:ListBucketVersions', { bucket: bucketName })

                        return listVersions(req, reply, bucket)
                    }
                    if (hasSubresource) {
                        await auth.authorize(req, principal, 's3:GetBucketLocation', { bucket: bucketName })

                        return bucketSubresource(req, reply, bucket)
                    }
                    await auth.authorize(req, principal, 's3:ListBucket', { bucket: bucketName })

                    return listBucket(req, reply, bucket)
                }
                if (req.method === 'PUT') {
                    if (hasSubresource) {
                        await auth.authorize(req, principal, 's3:PutBucketPolicy', { bucket: bucketName })

                        return bucketSubresource(req, reply, bucket)
                    }
                    // PUT on an existing bucket is idempotent (S3 behaviour)
                    await auth.authorize(req, principal, 's3:CreateBucket', { bucket: bucketName })
                    send(req, reply, '', { statusCode: 200, headers: { location: `/${bucketName}` } })

                    return reply.send('')
                }
                if (req.method === 'DELETE' && hasSubresource) {
                    await auth.authorize(req, principal, 's3:PutBucketPolicy', { bucket: bucketName })

                    return bucketSubresource(req, reply, bucket)
                }
                throw errors.methodNotAllowed(`${req.method} is not supported on buckets`)
            }

            // -------- object level
            if (req.method === 'PUT' && hasQuery(req, 'partNumber') && hasQuery(req, 'uploadId')) {
                await auth.authorize(req, principal, 's3:PutObject', { bucket: bucketName, key })

                return uploadPart(req, reply, bucket, key, queryValue(req, 'partNumber'), queryValue(req, 'uploadId'))
            }
            if (req.method === 'POST' && hasQuery(req, 'uploads')) {
                await auth.authorize(req, principal, 's3:PutObject', { bucket: bucketName, key })

                return initiateMultipart(req, reply, bucket, key)
            }
            if (req.method === 'POST' && hasQuery(req, 'uploadId')) {
                await auth.authorize(req, principal, 's3:PutObject', { bucket: bucketName, key })

                return completeMultipart(req, reply, bucket, key, queryValue(req, 'uploadId'))
            }
            if (req.method === 'GET' && hasQuery(req, 'uploadId')) {
                await auth.authorize(req, principal, 's3:ListMultipartUploadParts', { bucket: bucketName, key })

                return listParts(req, reply, bucket, key, queryValue(req, 'uploadId'))
            }
            if (req.method === 'DELETE' && hasQuery(req, 'uploadId')) {
                await auth.authorize(req, principal, 's3:AbortMultipartUpload', { bucket: bucketName, key })
                await objects.abortMultipart(bucket, queryValue(req, 'uploadId'))
                await auditFor(req, 's3.AbortMultipartUpload', bucket, key, { uploadId: queryValue(req, 'uploadId') })
                send(req, reply, '', { statusCode: 204 })

                return reply.send('')
            }
            const objectSub = ['tagging', 'retention', 'legal-hold', 'attributes', 'restore'].some((name) => hasQuery(req, name))
            if (objectSub) {
                if (req.method === 'GET') await auth.authorize(req, principal, 's3:GetObjectTagging', { bucket: bucketName, key })
                if (req.method === 'PUT') await auth.authorize(req, principal, 's3:PutObjectTagging', { bucket: bucketName, key })
                if (req.method === 'DELETE') await auth.authorize(req, principal, 's3:DeleteObjectTagging', { bucket: bucketName, key })

                return objectSubresource(req, reply, bucket, key)
            }
            if (req.method === 'GET' || req.method === 'HEAD') {
                const versionScoped = !!queryValue(req, 'versionId')
                await auth.authorize(req, principal, versionScoped ? 's3:GetObjectVersion' : 's3:GetObject', { bucket: bucketName, key })

                return headOrGet(req, reply, bucket, key)
            }
            if (req.method === 'PUT') {
                await auth.authorize(req, principal, 's3:PutObject', { bucket: bucketName, key })

                return putObject(req, reply, bucket, key)
            }
            if (req.method === 'DELETE') {
                await auth.authorize(req, principal, 's3:DeleteObject', { bucket: bucketName, key })

                return deleteObject(req, reply, bucket, key)
            }
            if (req.method === 'POST') {
                await auth.authorize(req, principal, 's3:PutObject', { bucket: bucketName, key })

                return putObject(req, reply, bucket, key)
            }
            throw errors.methodNotAllowed(`${req.method} is not supported on objects`)
        } catch (err) {
            if (!(err instanceof StorageError) || (err.statusCode || 500) >= 500) {
                logger.error?.({ err, url: req.url, method: req.method }, 's3 request failed')
            } else {
                logger.debug?.({ code: err.code, detail: err.detail, url: req.url, method: req.method }, 's3 request rejected')
            }

            return sendError(req, reply, err instanceof StorageError ? err : new StorageError('InternalError', err.message, { expose: false, cause: err }))
        }
    }

    return {
        dispatch, parseTarget, sendError, region, OWNER_ID, OWNER_NAME,
    }
}

module.exports = { createS3Server, S3_XMLNS }
