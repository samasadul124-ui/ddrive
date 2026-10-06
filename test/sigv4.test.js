/** SigV4 signer/verifier unit tests (no server). */
const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const sigv4 = require('../src/lib/sigv4')

const CREDENTIALS = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' }
const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

test('header signing produces the documented canonical request', () => {
    const canonical = sigv4.buildCanonical({
        method: 'GET',
        uri: '/',
        query: new URLSearchParams(),
        headers: { host: 'example.amazonaws.com', 'x-amz-date': '20150830T123600Z' },
        signedHeaders: 'host;x-amz-date',
        payloadHash: EMPTY,
    })

    // aws-sig-v4-test-suite case "get-vanilla"
    assert.equal(canonical, [
        'GET',
        '/',
        '',
        'host:example.amazonaws.com',
        'x-amz-date:20150830T123600Z',
        '',
        'host;x-amz-date',
        EMPTY,
    ].join('\n'))
})

test('signRequest sets the expected headers and signature format', () => {
    const headers = sigv4.signRequest({
        method: 'PUT', url: 'http://127.0.0.1:3111/s3/bucket/key.txt', payloadHash: EMPTY,
    }, CREDENTIALS, { region: 'us-east-1', service: 's3' })

    assert.equal(headers.host, '127.0.0.1:3111')
    assert.equal(headers['x-amz-content-sha256'], EMPTY)
    assert.match(headers['x-amz-date'], /^\d{8}T\d{6}Z$/)
    assert.match(
        headers.authorization,
        /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/us-east-1\/s3\/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$/,
    )
})

test('verifyRequest accepts a signed request and reports its scope', () => {
    const payloadHash = crypto.createHash('sha256').update('hello').digest('hex')
    const headers = sigv4.signRequest({
        method: 'PUT', url: 'http://127.0.0.1:3111/s3/bucket/key.txt', payloadHash,
    }, CREDENTIALS, { region: 'us-east-1', service: 's3' })

    const result = sigv4.verifyRequest({
        method: 'PUT', rawPath: '/s3/bucket/key.txt', query: '', headers, payloadHash,
    }, { region: 'us-east-1', secret: CREDENTIALS.secretAccessKey })

    assert.equal(result.ok, true)
    assert.equal(result.accessKeyId, CREDENTIALS.accessKeyId)
    assert.equal(result.payloadHash, payloadHash)
    assert.equal(result.isPresigned, false)
})

test('verifyRequest rejects a tampered signature and a stale date', () => {
    const payloadHash = EMPTY
    const headers = sigv4.signRequest({
        method: 'GET', url: 'http://127.0.0.1:3111/s3/bucket/key.txt', payloadHash,
    }, CREDENTIALS, { region: 'us-east-1', service: 's3' })

    // Flip the first signature character to one it is guaranteed not to be,
    // otherwise the "tampered" signature is occasionally the valid one (hex output).
    const signature = headers.authorization.slice(headers.authorization.indexOf('Signature=') + 'Signature='.length)
    const flipped = (signature[0] === '0' ? '1' : '0') + signature.slice(1)
    const tampered = { ...headers, authorization: headers.authorization.replace(/Signature=[0-9a-f]+$/, `Signature=${flipped}`) }
    assert.throws(
        () => sigv4.verifyRequest(
            { method: 'GET', rawPath: '/s3/bucket/key.txt', query: '', headers: tampered, payloadHash },
            { region: 'us-east-1', secret: CREDENTIALS.secretAccessKey },
        ),
        { code: 'SignatureDoesNotMatch' },
    )

    const old = sigv4.signRequest({
        method: 'GET', url: 'http://127.0.0.1:3111/s3/bucket/key.txt', payloadHash,
    }, CREDENTIALS, { region: 'us-east-1', service: 's3', date: new Date(Date.now() - 3600 * 1000) })
    assert.throws(
        () => sigv4.verifyRequest(
            { method: 'GET', rawPath: '/s3/bucket/key.txt', query: '', headers: old, payloadHash },
            { region: 'us-east-1', secret: CREDENTIALS.secretAccessKey },
        ),
        { code: 'RequestTimeTooSkewed' },
    )
})

test('presign produces a verifiable URL with query credentials', () => {
    const credentials = { ...CREDENTIALS, sessionToken: 'session-token' }
    const url = sigv4.presign({ method: 'GET', url: 'http://127.0.0.1:3111/s3/bucket/key.txt' }, credentials, { expiresIn: 300, region: 'us-east-1' })
    const parsed = new URL(url)

    assert.equal(parsed.searchParams.get('X-Amz-Algorithm'), 'AWS4-HMAC-SHA256')
    assert.equal(parsed.searchParams.get('X-Amz-Security-Token'), 'session-token')
    assert.ok(parsed.searchParams.get('X-Amz-Signature'))

    // a presigned GET is hashed with UNSIGNED-PAYLOAD by default and must verify
    const headers = { host: parsed.host }
    const result = sigv4.verifyRequest({
        method: 'GET', rawPath: parsed.pathname, query: parsed.searchParams, headers, payloadHash: '',
    }, { region: 'us-east-1', secret: CREDENTIALS.secretAccessKey })

    assert.equal(result.ok, true)
    assert.equal(result.isPresigned, true)
    assert.equal(result.payloadHash, sigv4.UNSIGNED_PAYLOAD)
})

test('aws-chunked bodies are decoded and chunk signatures checked', async () => {
    const amzDate = '20260102T030405Z'
    const dateStamp = '20260102'
    const region = 'us-east-1'
    const scope = `${dateStamp}/${region}/s3/aws4_request`
    const signingKey = sigv4.signingKey(CREDENTIALS.secretAccessKey, dateStamp, region, 's3')

    // one chunk signature = HMAC(signingKey, stringToSign) where stringToSign
    // chains the previous chunk signature (empty for the first chunk)
    const sign = (previous, data) => crypto.createHmac('sha256', signingKey).update([
        'AWS4-HMAC-SHA256-PAYLOAD',
        amzDate,
        scope,
        previous,
        sigv4.EMPTY_SHA256,
        crypto.createHash('sha256').update(data).digest('hex'),
    ].join('\n'), 'utf8').digest('hex')

    const first = 'hello '
    const second = 'world'
    const firstSignature = sign('', first)
    const secondSignature = sign(firstSignature, second)
    const finalSignature = sign(secondSignature, '')
    const chunked = Buffer.from([
        `${first.length.toString(16)};chunk-signature=${firstSignature}\r\n${first}\r\n`,
        `${second.length.toString(16)};chunk-signature=${secondSignature}\r\n${second}\r\n`,
        `0;chunk-signature=${finalSignature}\r\n\r\n`,
    ].join(''), 'utf8')

    const stream = sigv4.decodeChunkedStream(require('stream').Readable.from([chunked]), {
        signingKey, amzDate, dateStamp, region,
    })
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)

    assert.equal(Buffer.concat(chunks).toString(), 'hello world')
    assert.equal(sigv4.isChunked({ 'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD' }), true)
    assert.equal(sigv4.isChunked({ 'content-encoding': 'aws-chunked' }), true)
    assert.equal(sigv4.isChunked({ 'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }), false)
})

test('decodeChunkedStream rejects a forged chunk signature', async () => {
    const signingKey = sigv4.signingKey(CREDENTIALS.secretAccessKey, '20260102', 'us-east-1', 's3')
    const chunked = Buffer.from('5;chunk-signature=deadbeef\r\nhello\r\n0;chunk-signature=deadbeef\r\n\r\n', 'utf8')
    const stream = sigv4.decodeChunkedStream(require('stream').Readable.from([chunked]), {
        signingKey, amzDate: '20260102T030405Z', dateStamp: '20260102', region: 'us-east-1',
    })

    await assert.rejects(async () => {
        // eslint-disable-next-line no-unused-vars, no-empty
        for await (const chunk of stream) void chunk
    }, { code: 'SignatureDoesNotMatch' })
})
