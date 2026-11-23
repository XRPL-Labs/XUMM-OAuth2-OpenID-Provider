// Run: node test/signinInstruction.test.js
//
// The text of the sign request (`Sign in to <host>`): the host of the redirect URI and nothing else of it.
// First the function, then the real start of a sign-in (fn/xummSignin.js) with a fake config, datastore and SDK.
const assert = require('assert')
const Module = require('module')
const signinInstruction = require('../fn/signinInstruction')

let n = 0
const eq = (a, b, message) => { assert.strictEqual(a, b, message); n++ }

const CLIENT = '11111111-2222-4333-8444-555555555555'

// [redirect URI, text]
const cases = [
  // As before
  ['https://app.example', 'Sign in to app.example'],
  ['https://app.example/', 'Sign in to app.example'],
  ['https://app.example/cb', 'Sign in to app.example'],
  ['https://app.example/auth/callback?x=1#y', 'Sign in to app.example'],
  ['https://sub.app.example:8443/cb', 'Sign in to sub.app.example:8443'],
  ['http://localhost:3000', 'Sign in to localhost:3000'],
  ['http://localhost:5173/auth/callback', 'Sign in to localhost:5173'],
  ['http://127.0.0.1:5173/', 'Sign in to 127.0.0.1:5173'],
  ['http://192.168.1.131:3000/', 'Sign in to 192.168.1.131:3000'],
  ['http://[::1]:3000/cb', 'Sign in to [::1]:3000'],
  ['https://app-pr-123-team.vercel.app/cb', 'Sign in to app-pr-123-team.vercel.app'],
  ['https://xrp.589.workers.dev', 'Sign in to xrp.589.workers.dev'],
  ['myapp://callback', 'Sign in to callback'],
  ['myapp://callback/done', 'Sign in to callback'],
  ['allthemarket://xaman-callback', 'Sign in to xaman-callback'],
  ['com.example.app://oauth_cb/x', 'Sign in to oauth_cb'],
  ['myapp:/callback', 'Sign in to myapp:'],

  // The host as a URL parser reads it: small letters, no default port, the ASCII form of a name
  ['https://App.Example/cb', 'Sign in to app.example'],
  ['HTTPS://APP.EXAMPLE/cb', 'Sign in to app.example'],
  ['https://app.example:443/cb', 'Sign in to app.example'],
  ['http://app.example:80', 'Sign in to app.example'],
  ['https://bücher.example/cb', 'Sign in to xn--bcher-kva.example'],

  // Only the host: nothing of the query, the fragment or the path, with or without a `/` before it
  ['https://app.example?x=1', 'Sign in to app.example'],
  ['https://app.example#y', 'Sign in to app.example'],
  ['https://app.example?', 'Sign in to app.example'],
  ['https://app.example# Some other text: do this next', 'Sign in to app.example'],
  ['https://app.example? Some other text', 'Sign in to app.example'],
  ['https://app.example?a=<b>text</b>', 'Sign in to app.example'],
  ['https://app.example:8443?text here#and here', 'Sign in to app.example:8443'],
  ['https://app.example/?text', 'Sign in to app.example'],
  ['https://app.example\\text', 'Sign in to app.example'],
  ['  https://app.example/cb  ', 'Sign in to app.example'],
  ['myapp://callback?text here', 'Sign in to callback'],
  ['myapp://callback#text here', 'Sign in to callback'],

  // A custom scheme without a host: the scheme
  ['myapp://', 'Sign in to myapp:'],
  ['myapp:///path', 'Sign in to myapp:'],
  ['myapp:callback', 'Sign in to myapp:'],

  // No host that can be shown: the text without a host
  ['', 'Sign in'],
  ['not a uri', 'Sign in'],
  ['/relative/path', 'Sign in'],
  ['https://', 'Sign in'],
  ['https://app.example with text', 'Sign in'],
  ['https://app.example<b>', 'Sign in'],
  ['myapp://some text', 'Sign in'],
  ['myapp://some%20text', 'Sign in'],
  ['myapp://text!(here)', 'Sign in'],
  ['https://' + 'a'.repeat(60) + '.' + 'b'.repeat(60) + '.example', 'Sign in'],
  ['myapp://' + 'a'.repeat(101), 'Sign in'],
]

for (const [uri, text] of cases) eq(signinInstruction(uri), text, JSON.stringify(uri))

// The longest host that is shown
eq(signinInstruction('myapp://' + 'a'.repeat(100)), 'Sign in to ' + 'a'.repeat(100))

// Not a text
for (const value of [undefined, null, 5, {}, ['https://app.example'], true]) eq(signinInstruction(value), 'Sign in', typeof value)

// Every text: `Sign in`, or `Sign in to ` and a host of letters, digits and . _ : [ ] - only, 100 characters at most
for (const [uri] of cases) {
  const text = signinInstruction(uri)
  assert.ok(/^Sign in( to [A-Za-z0-9._:[\]-]{1,100})?$/.test(text), JSON.stringify(uri) + ' -> ' + text)
  n++
}

// ---- The start of a sign-in: the sign request that is made has this text
const fakeConfig = { secret: 'test-secret', openid: { discovery: { issuer: 'https://oauth2.test' } } }
const stored = []
const datastore = {
  createQuery: () => ({ filter () { return this } }),
  runQuery: async () => [[{ 'client-id': CLIENT, 'client-secret': 'secret-of-the-client' }]],
  upsert: async data => { stored.push(data) }
}
const created = []
class XummSdk {
  constructor () {
    this.payload = {
      create: async payload => {
        created.push(payload)
        return { uuid: '00000000-0000-4000-8000-' + String(created.length).padStart(12, '0'), next: { always: 'https://xumm.test/sign/' + created.length } }
      }
    }
  }
}

const load = Module._load
Module._load = function (request) {
  if (/^\.\.?\/config$/.test(request)) return fakeConfig
  if (/^\.\.?\/datastore$/.test(request)) return { datastore, db: {} }
  if (request === 'xumm-sdk') return { XummSdk }
  return load.apply(this, arguments)
}

const realLog = console.log
console.log = () => {}
const { initiateXummSignin } = require('../fn/xummSignin')

;(async () => {
  for (const [uri, text] of [
    ['https://app.example/cb', 'Sign in to app.example'],
    ['https://app.example:8443/cb?x=1#y', 'Sign in to app.example:8443'],
    ['https://app.example# Some other text: do this next', 'Sign in to app.example'],
    ['https://app.example?text <b>here</b>', 'Sign in to app.example'],
    ['http://localhost:3000', 'Sign in to localhost:3000'],
    ['myapp://callback/done', 'Sign in to callback'],
    ['myapp://', 'Sign in to myapp:'],
  ]) {
    const req = { query: { client_id: CLIENT, redirect_uri: uri, response_type: 'code', state: 'state-1' } }
    const res = { redirected: [] }
    res.redirect = url => { res.redirected.push(url) }
    await initiateXummSignin(req, res)

    const payload = created[created.length - 1]
    eq(payload.custom_meta.instruction, text, JSON.stringify(uri))
    assert.deepStrictEqual(Object.keys(payload.custom_meta), ['instruction']); n++
    eq(payload.txjson.TransactionType, 'SignIn')
    eq(res.redirected.length, 1, 'the user is sent to the sign request')
    // The redirect URI of the request is stored as it came: the return step sends the user there (as before)
    eq(JSON.parse(stored[stored.length - 1].fields.params).redirect_uri, uri)
  }

  realLog('signinInstruction:', n, 'checks OK')
})().catch(e => {
  realLog(e)
  process.exit(1)
})
