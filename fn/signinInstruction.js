// The text of the sign request: `Sign in to <host>`.
// The host is the host (with the port, when it is not the default one) of the redirect URI as a URL parser reads it:
// the place the user goes back to. Nothing else of the redirect URI is in the text (no path, query or fragment).
//
// https://example.com/cb?x=1#y       Sign in to example.com
// https://Example.com:8443/cb        Sign in to example.com:8443
// http://localhost:3000              Sign in to localhost:3000
// myapp://callback/done              Sign in to callback
// myapp:/callback  or  myapp://      Sign in to myapp:        (a custom scheme without a host: the scheme)
// Not a URI, or a host with other characters or over the length limit: `Sign in`
const HOST = /^[A-Za-z0-9._:[\]-]+$/
const MAX_HOST_LENGTH = 100

const redirectHost = function redirectHost (redirectUri) {
  if (typeof redirectUri !== 'string') return ''
  try {
    const u = new URL(redirectUri)
    const host = u.host !== '' ? u.host : u.protocol
    return host.length <= MAX_HOST_LENGTH && HOST.test(host) ? host : ''
  } catch (e) {
    return ''
  }
}

module.exports = function signinInstruction (redirectUri) {
  const host = redirectHost(redirectUri)
  return host === '' ? 'Sign in' : 'Sign in to ' + host
}

Object.assign(module.exports, { redirectHost })
