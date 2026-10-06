/**
 * Error type shared by every DDrive surface (REST / WebDAV / S3 / console).
 *
 * `code` maps 1:1 onto the S3 XML error code space and onto WebDAV status
 * codes, so a single error object can be rendered natively by each protocol.
 */
const STATUS_BY_CODE = {
    AccessDenied: 403,
    AccountProblem: 403,
    AuthorizationHeaderMalformed: 400,
    BadDigest: 400,
    BadRequest: 400,
    BucketAlreadyExists: 409,
    BucketAlreadyOwnedByYou: 409,
    BucketNotEmpty: 409,
    Conflict: 409,
    EntityTooLarge: 400,
    EntityTooSmall: 400,
    ExpiredToken: 400,
    IllegalVersioningConfiguration: 400,
    IncompleteBody: 400,
    InternalError: 500,
    InvalidAccessKeyId: 403,
    InvalidArgument: 400,
    InvalidBucketName: 400,
    InvalidDigest: 400,
    InvalidPart: 400,
    InvalidPartOrder: 400,
    InvalidRange: 416,
    InvalidRequest: 400,
    InvalidTag: 400,
    InvalidURI: 400,
    KeyTooLong: 400,
    Locked: 423,
    MalformedXML: 400,
    MethodNotAllowed: 405,
    MissingContentLength: 411,
    MissingRequestBodyError: 400,
    MissingSecurityHeader: 400,
    NoSuchBucket: 404,
    NoSuchBucketPolicy: 404,
    NoSuchKey: 404,
    NoSuchObjectLockConfiguration: 404,
    NoSuchSubresource: 404,
    NoSuchLifecycleConfiguration: 404,
    NoSuchReplicationConfiguration: 404,
    NoSuchTagSet: 404,
    NoSuchUpload: 404,
    NoSuchVersion: 404,
    NotImplemented: 501,
    ObjectLockConfigurationNotFoundError: 404,
    ObjectLocked: 423,
    PermanentRedirect: 301,
    PreconditionFailed: 412,
    QuotaExceeded: 507,
    RequestTimeTooSkewed: 403,
    RequestTimeout: 400,
    ServiceUnavailable: 503,
    SignatureDoesNotMatch: 403,
    SlowDown: 503,
    StorageFull: 507,
    TooManyBuckets: 400,
    TooManyRequests: 429,
    Unauthorized: 401,
    UnsupportedMediaType: 415,
    UserKeyExists: 409,
    NoSuchUser: 404,
    NoSuchGroup: 404,
    NoSuchRole: 404,
    UserAlreadyExists: 409,
    InvalidPart: 400,
    InvalidPartOrder: 400,
    InvalidTag: 400,
    NoSuchPolicy: 404,
    NoSuchShare: 404,
    MissingParameter: 400,
    ValidationError: 400,
    XAmzContentSHA256Mismatch: 400,
    XAmzDecodedContentLengthMismatch: 400,
    InternalServerError: 500,
    NotFound: 404,
    Forbidden: 403,
    RangeNotSatisfiable: 416,
}

class StorageError extends Error {
    /**
     * @param {string} code S3 style error code, e.g. "NoSuchKey"
     * @param {string} [message]
     * @param {object} [opts] { statusCode, detail, expose, resource, requestId }
     */
    constructor(code, message, opts = {}) {
        super(message || code)
        this.name = 'StorageError'
        this.code = code
        this.statusCode = opts.statusCode || STATUS_BY_CODE[code] || 500
        this.expose = opts.expose !== undefined ? opts.expose : this.statusCode < 500
        this.detail = opts.detail
        this.resource = opts.resource
        if (opts.cause) this.cause = opts.cause
        Error.captureStackTrace?.(this, StorageError)
    }

    toJSON() {
        return {
            code: this.code,
            message: this.expose ? this.message : 'Internal server error',
            detail: this.detail,
            resource: this.resource,
        }
    }
}

const errors = {
    accessDenied: (msg = 'Access Denied', detail) => new StorageError('AccessDenied', msg, { detail }),
    noSuchKey: (key) => new StorageError('NoSuchKey', 'The specified key does not exist.', { detail: { key } }),
    noSuchBucket: (bucket) => new StorageError('NoSuchBucket', 'The specified bucket does not exist.', { detail: { bucket } }),
    noSuchVersion: (versionId) => new StorageError('NoSuchVersion', 'The specified version does not exist.', { detail: { versionId } }),
    noSuchUpload: (uploadId) => new StorageError('NoSuchUpload', 'The specified multipart upload does not exist.', { detail: { uploadId } }),
    noSuchUser: (username) => new StorageError('NoSuchUser', `User ${username} does not exist.`, { detail: { username } }),
    userExists: (username) => new StorageError('UserAlreadyExists', `User ${username} already exists.`, { statusCode: 409, detail: { username } }),
    invalidPart: (partNumber) => new StorageError('InvalidPart', `Part ${partNumber} is not a valid uploaded part.`, { statusCode: 400, detail: { partNumber } }),
    invalidPartOrder: () => new StorageError('InvalidPartOrder', 'The list of parts was not in ascending order.', { statusCode: 400 }),
    invalidTag: (message = 'The tag set is not valid.') => new StorageError('InvalidTag', message, { statusCode: 400 }),
    notModified: (message = 'Not modified') => new StorageError('NotModified', message, { statusCode: 304 }),
    noSuchGroup: (name) => new StorageError('NoSuchGroup', `Group ${name} does not exist.`, { detail: { name } }),
    noSuchRole: (name) => new StorageError('NoSuchRole', `Role ${name} does not exist.`, { detail: { name } }),
    noSuchPolicy: (name) => new StorageError('NoSuchPolicy', `Policy ${name} does not exist.`, { detail: { name } }),
    noSuchShare: (token) => new StorageError('NoSuchShare', 'The share link does not exist or has expired.', { detail: { token } }),
    bucketNotEmpty: (bucket) => new StorageError('BucketNotEmpty', 'The bucket you tried to delete is not empty.', { detail: { bucket } }),
    bucketAlreadyExists: (bucket) => new StorageError('BucketAlreadyExists', 'The requested bucket name is not available.', { detail: { bucket } }),
    invalidArgument: (message, detail) => new StorageError('InvalidArgument', message, { detail }),
    invalidRequest: (message, detail) => new StorageError('InvalidRequest', message, { detail }),
    notImplemented: (message) => new StorageError('NotImplemented', message, { statusCode: 501 }),
    preconditionFailed: (message = 'At least one of the pre-conditions you specified did not hold', detail) => new StorageError('PreconditionFailed', message, { detail }),
    invalidRange: (size) => new StorageError('InvalidRange', 'The requested range is not satisfiable', { detail: { size } }),
    quotaExceeded: (message = 'Storage quota exceeded') => new StorageError('QuotaExceeded', message, { statusCode: 507 }),
    objectLocked: (message = 'Object is protected by an object lock or legal hold', detail) => new StorageError('ObjectLocked', message, { statusCode: 423, detail }),
    methodNotAllowed: (message = 'Method not allowed') => new StorageError('MethodNotAllowed', message, { statusCode: 405 }),
    conflict: (message, detail) => new StorageError('Conflict', message, { statusCode: 409, detail }),
    validation: (message, detail) => new StorageError('ValidationError', message, { statusCode: 400, detail }),
    tooManyRequests: (message = 'Please reduce your request rate') => new StorageError('TooManyRequests', message, { statusCode: 429 }),
    internal: (message = 'Internal server error', cause) => new StorageError('InternalError', message, { statusCode: 500, expose: false, cause }),
}

module.exports = { StorageError, STATUS_BY_CODE, errors }
