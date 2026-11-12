const sanitizeRedirectUri = require('./sanitizeRedirectUri')

// A redirect URI is allowed when it has the SAME origin (scheme, host, port) as a registered one, and its path starts
// with the registered path. Before 2026-11 this was a string prefix match: registered `https://example.com` also
// allowed `https://example.com.attacker.net`, `https://example.com@attacker.net` and `https://example.comm`, so any
// site could receive the sign in result (and the token) of any application. (Seen: 848 sign ins with such URIs on
// 16 applications, September - November 2026.)
//
// Registered                         Allows
// https://example.com                https://example.com, any path. Not another host, scheme or port.
// https://example.com/cb             paths that start with /cb (https://example.com/* : any path)
// http://localhost                   any port (loopback without a port, RFC 8252 7.3); with a port: that port
// https://*.example.com              subdomains of example.com (not example.com itself)
// https://app-*.vercel.app           one label that starts with `app-` (preview deployments)
// myapp://callback                   that host of the custom scheme, any path
// myapp://                           every URI of the custom scheme (the scheme belongs to the app on the device)
// https://  or  http://              NOTHING (was: every site). Register the real sites.
const HTTP = new Set(['http:', 'https:'])
const PLACEHOLDER = 'wildcard-label-placeholder'
// Second level names that are part of the public suffix under a two letter TLD (`*.co.uk` must not match every site)
const GENERIC_SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'or', 'ne'])

const parse = uri => {
  try {
    const u = new URL(String(uri))
    // No user info (`https://example.com@attacker.net`); a web URI needs a host
    if (u.username !== '' || u.password !== '') return null
    if (HTTP.has(u.protocol) && u.hostname === '') return null
    return u
  } catch (e) {
    return null
  }
}

// The path starts with the registered path (as before: `/call` allows `/callback`). Inside one origin the path is not a
// security boundary; the URL parser already resolved `..` and `.`.
const pathAllowed = (registered, requested) => {
  // `/cb/*` is `/cb/` (a `*` at the end of the path was never a pattern: such entries matched nothing before)
  const r = registered.replace(/\*+$/, '').replace(/\/+$/, '')
  if (r === '') return true
  if (/%2f|%5c|%2e|\\/i.test(requested)) return false
  return requested.startsWith(r)
}

// Loopback (development): registered WITHOUT a port allows any port, as the prefix match did
const loopback = host => host === 'localhost' || host === '127.0.0.1' || host === '[::1]'

// Host with wildcards. A label `*`: one or more labels. `*` inside a label (`app-*`): the rest of that one label.
// The registrable part (the last two labels, three for names like `example.co.uk`) has no wildcard.
const wildcardHostAllowed = (pattern, host) => {
  const labels = pattern.split('.')
  const fixed = labels.length >= 3 && labels[labels.length - 1].length === 2 && GENERIC_SECOND_LEVEL.has(labels[labels.length - 2]) ? 3 : 2
  if (labels.length <= fixed || labels.slice(-fixed).some(l => l.includes('*') || l === '')) return false
  const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const source = labels.map(label => {
    if (/^\*+$/.test(label)) return '[a-z0-9-]+(?:\\.[a-z0-9-]+)*'
    return label.split(/\*+/).map(escape).join('[a-z0-9-]+')
  }).join('\\.')
  return new RegExp('^' + source + '$').test(host)
}

const uriAllowed = (registered, requested) => {
  const u = parse(requested)
  if (!u) return false

  // `myapp://` (stored as `myapp:`): every URI of that custom scheme. Never for http / https.
  const bare = String(registered).match(/^([a-z][a-z0-9+.-]*):(\/\/)?$/i)
  if (bare) {
    const protocol = bare[1].toLowerCase() + ':'
    return !HTTP.has(protocol) && u.protocol === protocol
  }

  // A `*` in the host is not valid for the URL parser: parse with a placeholder, put the `*` back
  const parts = String(registered).match(/^([a-z][a-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/i)
  const wildcard = !!parts && parts[2].includes('*')
  const r = parse(wildcard ? parts[1] + parts[2].replace(/\*+/g, PLACEHOLDER) + parts[3] : registered)
  if (!r) return false

  if (r.protocol !== u.protocol) return false
  const registeredHost = (wildcard ? r.hostname.split(PLACEHOLDER).join('*') : r.hostname).toLowerCase()
  const requestedHost = u.hostname.toLowerCase()
  if (r.port !== u.port && !(r.port === '' && loopback(registeredHost) && registeredHost === requestedHost)) return false
  if (wildcard ? !wildcardHostAllowed(registeredHost, requestedHost) : registeredHost !== requestedHost) return false
  return pathAllowed(r.pathname, u.pathname)
}

module.exports = function redirectUriCheck(dbresult, uri) {
  if (typeof uri !== 'string' || uri === '') return false
  const registered = dbresult?.[0]?.[0]?.['redirect-url']
  if (typeof registered !== 'string') return false

  // One URI per line. Developers also wrote several on one line (space, comma, semicolon, `<br/>`) or added a note
  // after the URI: a URI has no space, so every part that looks like a URI counts.
  const uris = registered.split(/[\s,;]+|<br\s*\/?>/i)
    .map(u => String(u || '').trim())
    .filter(u => u.match(/^[a-z0-9]{1,}[a-z0-9]{1,}:\//))
    .map(u => sanitizeRedirectUri(u))

  const sUri = sanitizeRedirectUri(uri)
  return uris.some(allowed => uriAllowed(allowed, sUri)) ? dbresult : false
}

Object.assign(module.exports, { uriAllowed })
