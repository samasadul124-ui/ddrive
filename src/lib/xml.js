/**
 * XML helpers shared by the S3 and WebDAV servers.
 *
 * `parseXml` strips namespace prefixes (so `D:propfind`, `s3:ListBucket` and
 * `ListBucket` are all the same node) and never coerces scalar values, which
 * keeps S3 keys such as "0123" or "true" intact.
 */
const { XMLParser, XMLBuilder } = require('fast-xml-parser')

const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    textNodeName: '#text',
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: true,
    removeNSPrefix: true,
    allowBooleanAttributes: true,
    stopNodes: [],
})

const builder = new XMLBuilder({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    textNodeName: '#text',
    format: false,
    suppressEmptyNode: true,
    suppressBooleanAttributes: false,
})

const parseXml = (input) => {
    if (input === undefined || input === null) return {}
    const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input)
    if (!text.trim()) return {}
    try {
        return parser.parse(text)
    } catch (err) {
        const { errors } = require('./errors')

        throw errors.invalidArgument(`Malformed XML: ${err.message}`)
    }
}

const buildXml = (obj, { declaration = false } = {}) => {
    const body = builder.build(obj)

    return declaration ? `<?xml version="1.0" encoding="UTF-8"?>${body}` : body
}

/** First child node matching `name` (namespace prefix already stripped). */
const node = (parent, name) => {
    if (!parent || typeof parent !== 'object') return undefined

    return parent[name]
}

/** Always an array of child nodes matching `name`. */
const nodes = (parent, name) => {
    const value = node(parent, name)
    if (value === undefined || value === null) return []

    return Array.isArray(value) ? value : [value]
}

/** Text of a node that may be a string, `{ '#text': ... }` or an array. */
const text = (value) => {
    if (value === undefined || value === null) return undefined
    if (Array.isArray(value)) return value.length ? text(value[0]) : undefined
    if (typeof value === 'object') {
        if (value['#text'] !== undefined) return String(value['#text'])
        // <Owner><ID>abc</ID></Owner> - fall back to the first scalar child
        const first = Object.keys(value).find((k) => !k.startsWith('@_'))

        return first ? text(value[first]) : undefined
    }

    return String(value)
}

/** All keys of an object that are elements (not attributes / text). */
const collectNames = (obj) => (obj && typeof obj === 'object' ? Object.keys(obj).filter((k) => !k.startsWith('@_') && k !== '#text') : [])

module.exports = {
    parseXml, buildXml, node, nodes, text, collectNames, parser, builder,
}
