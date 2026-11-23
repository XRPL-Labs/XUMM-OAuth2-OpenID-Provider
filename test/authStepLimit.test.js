// Run: node test/authStepLimit.test.js
//
// The start of a sign-in (/auth), through the real route functions of functions.js: the limit on starts per caller
// address and per client, the checks of the request before a sign request is created, and the error answers.
// No config file, no database, no network: the config, the datastore and the Xaman SDK are fakes (as in
// signinSingleUse.test.js).
const assert = require('assert')
const crypto = require('crypto')
const Module = require('module')
const path = require('path')
const { spawnSync } = require('child_process')

const CLIENT_A = '11111111-2222-4333-8444-aaaaaaaaaaaa'
const CLIENT_B = '11111111-2222-4333-8444-bbbbbbbbbbbb'
const CLIENT_FORM = '11111111-2222-4333-8444-cccccccccccc' // user name + password form, no sign request
const REDIRECT = 'https://app.example/cb'
const SECOND = 1000

// ---- Fake config (the shape of config.sample.js)
const fakeConfig = {
  port: 0,
  secret: crypto.randomBytes(32).toString('base64'),
  db: { uri: 'mysql://none' },
  maildomain: 'oauth2.test',
  jwt: {
    ISSUER: 'https://oauth2.test',
    JWT_LIFE_SPAN: 7200,
    CODE_LIFE_SPAN: 600,
    PRIVATE_KEY: crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    }).privateKey
  },
  openid: { discovery: { issuer: 'https://oauth2.test' }, certs: [] }
}

// ---- Fake datastore: the methods of datastore.js that the /auth handlers use, on arrays
let tables
let failQuery = false

// As the database: text is equal without a difference between capitals and small letters, a list is no value
const sqlEqual = (a, b) => {
  if (a === null || a === undefined || b === null || b === undefined) return false
  if (typeof a === 'object' || typeof b === 'object') throw new Error('SQL text that must stay in the log')
  const text = v => String(typeof v === 'boolean' ? Number(v) : v).toLowerCase()
  return text(a) === text(b)
}

class FakeQuery {
  constructor (dataset) {
    this.dataset = dataset
    this.filters = []
  }

  filter (key, operator, value) {
    this.filters.push({ key, operator, value })
    return this
  }

  async get () {
    await new Promise(resolve => setImmediate(resolve))
    return tables[this.dataset].filter(r => this.filters.every(f => sqlEqual(r[f.key], f.value))).map(r => ({ ...r }))
  }
}

const datastore = {
  createQuery: dataset => new FakeQuery(dataset),
  // As datastore.js: an error of the query is logged there, the answer is "no rows". `failQuery`: an error that
  // comes out of it all the same.
  async runQuery (query) {
    if (failQuery) throw new Error('SQL text that must stay in the log')
    try {
      return [await query.get()]
    } catch (e) {
      return [[]]
    }
  },
  key: ([k, v]) => ({ [k]: v }),
  async upsert (data) {
    const row = {}
    Object.keys(data).forEach(k => Object.assign(row, data[k]))
    if (!row.payload) throw new Error('Error, unknown dataset to upsert to')
    tables.xumm_challenge.push({ consumed: 0, ...row })
  }
}

// ---- Fake Xaman SDK: every created sign request is counted
const sdk = { created: [], noPayload: false }
class XummSdk {
  constructor (key, secret) {
    this.payload = {
      create: async payload => {
        const uuid = crypto.randomUUID()
        sdk.created.push({ uuid, key, secret, instruction: payload.custom_meta.instruction })
        if (sdk.noPayload) return null // the SDK gives null when the API gave no payload
        return { uuid, next: { always: 'https://xumm.test/sign/' + uuid } }
      }
    }
  }
}

const load = Module._load
Module._load = function (request) {
  if (/^\.\.?\/config$/.test(request)) return fakeConfig
  if (/^\.\.?\/datastore$/.test(request)) return { datastore, db: {} }
  if (request === 'xumm-sdk') return { XummSdk }
  if (request === 'mysql2/promise') return { createPool: () => ({}) }
  return load.apply(this, arguments)
}

const realLog = console.log
const logged = []
console.log = (...args) => { logged.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ')) }
const { auth, signin } = require('../functions')
const limitModule = require('../fn/authStartLimit')
const { authStartLimit, createAuthStartLimit, callerAddress } = limitModule

// The clock of this host
const clock = { offset: 0 }
const realNow = Date.now
Date.now = () => realNow() + clock.offset
// Every part of the suite starts in a new window: nothing of the part before it counts
const newWindow = () => { clock.offset += 10 * 60 * SECOND }

const unhandled = []
process.on('unhandledRejection', e => unhandled.push(e))

// ---- Request / response
let n = 0
const ok = (value, message) => { assert.ok(value, message); n++ }
const eq = (a, b, message) => { assert.strictEqual(a, b, message); n++ }

// `address`: the caller, as the proxy gives it in the request header. `brokenStatus`: the first res.status() fails.
const call = async (route, { query = {}, body = {}, method = 'GET', json = false, address, brokenStatus = false }) => {
  const req = { method, query, body, headers: address === undefined ? {} : { [limitModule.CALLER_ADDRESS_HEADER]: address }, server2server: json }
  const res = { statusCode: 200, headersSent: false, headers: {} }
  const answered = new Promise(resolve => { res.end = resolve })
  const answer = (kind, value) => {
    assert.strictEqual(res.headersSent, false, 'one answer per request')
    Object.assign(res, { headersSent: true, kind, value })
    res.end()
  }
  let statusFails = brokenStatus
  res.status = code => {
    if (statusFails) {
      statusFails = false
      throw new Error('the answer could not be written')
    }
    res.statusCode = code
    return res
  }
  res.setHeader = (name, value) => { res.headers[name.toLowerCase()] = value }
  res.send = html => { answer('html', String(html)); return res }
  res.json = data => { answer('json', data); return res }
  res.redirect = url => { res.statusCode = 302; answer('redirect', url) }
  route(req, res)
  let timer
  await Promise.race([answered, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('no answer to the request')), 3000) })])
  clearTimeout(timer)
  await new Promise(resolve => setImmediate(resolve))
  return { req, res }
}

const challenge = verifier => crypto.createHash('sha256').update(verifier).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
const IMPLICIT = { response_type: 'token', scope: 'XummPkce', state: 'state-1', nonce: 'nonce-1' } // the browser SDK
const CODE = { response_type: 'code', scope: 'openid', state: 'state-1' }
const CODE_PKCE = { ...CODE, code_challenge: challenge('verifier-1'), code_challenge_method: 'S256' }
const FLOWS = [IMPLICIT, CODE, CODE_PKCE]

const startQuery = (flow, client) => ({ client_id: client || CLIENT_A, redirect_uri: REDIRECT, ...(flow || IMPLICIT) })
const start = (address, flow, client, options) => call(auth, { query: startQuery(flow, client), address, ...options })

// A start that is allowed: as before, the user is sent to a new sign request, the challenge row is stored
const started = async (address, flow, client) => {
  const requests = sdk.created.length
  const rows = tables.xumm_challenge.length
  const { res } = await start(address, flow, client)
  eq(res.kind, 'redirect', 'the start sends the user to the sign request')
  eq(sdk.created.length, requests + 1, 'one sign request')
  eq(res.value, 'https://xumm.test/sign/' + sdk.created[requests].uuid)
  eq(tables.xumm_challenge.length, rows + 1, 'one challenge row')
  return res
}
// A start over the limit: 429, the error page (or JSON), no sign request and no row
const limited = async (address, flow, client, options) => {
  const requests = sdk.created.length
  const rows = tables.xumm_challenge.length
  const { res } = await start(address, flow, client, options)
  eq(res.statusCode, 429, 'over the limit')
  eq(sdk.created.length, requests, 'no sign request')
  eq(tables.xumm_challenge.length, rows, 'no challenge row')
  const retryAfter = Number(res.headers['retry-after'])
  ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60, 'Retry-After in seconds: ' + res.headers['retry-after'])
  if (options?.json) {
    eq(res.kind, 'json')
    eq(res.value.error, 'too_many_requests')
    eq(res.value.error_description, 'Too many sign in requests. Please try again in a minute.')
  } else {
    eq(res.kind, 'html', 'the error page')
    ok(/Error: too_many_requests/.test(res.value) && /Too many sign in requests\. Please try again in a minute\./.test(res.value), 'the text of the error page')
  }
  return res
}
// A request that is refused for its own values: no sign request, no row
const refused = async (query, status, description) => {
  const requests = sdk.created.length
  const rows = tables.xumm_challenge.length
  const { res } = await call(auth, { query, json: true, address: '198.51.100.99' })
  eq(res.statusCode, status, JSON.stringify(query))
  if (description) eq(res.value.error_description, description)
  eq(sdk.created.length, requests, 'no sign request: ' + JSON.stringify(query))
  eq(tables.xumm_challenge.length, rows, 'no challenge row')
  return res
}

const PER_ADDRESS = limitModule.AUTH_START_MAX_PER_ADDRESS
const PER_CLIENT = limitModule.AUTH_START_MAX_PER_CLIENT
const WINDOW = limitModule.AUTH_START_WINDOW_MS

const newTables = () => ({
  client: [CLIENT_A, CLIENT_B, CLIENT_FORM].map(id => ({
    'client-id': id, 'client-secret': 'secret-of-' + id, 'redirect-url': REDIRECT, 'implicit-enabled': 1, 'ac-enabled': 1, 'acpkce-enabled': 1, 'signin-method': id === CLIENT_FORM ? 'FORM' : 'XUMMAPI'
  })),
  xumm_challenge: []
})

const suite = async () => {
  tables = newTables()
  eq(PER_ADDRESS, 60)
  eq(PER_CLIENT, 600)
  eq(WINDOW, 60 * SECOND)
  eq(limitModule.CALLER_ADDRESS_HEADER, 'cf-connecting-ip')

  // 1. Under the limit: as before, for every flow. The sign request is made with the key and secret of the client.
  {
    for (let i = 0; i < PER_ADDRESS; i++) await started('192.0.2.1', FLOWS[i % FLOWS.length])
    const last = sdk.created[sdk.created.length - 1]
    eq(last.key, CLIENT_A)
    eq(last.secret, 'secret-of-' + CLIENT_A)
    eq(last.instruction, 'Sign in to app.example')
    const row = tables.xumm_challenge[tables.xumm_challenge.length - 1]
    eq(row.client, CLIENT_A)
    eq(row.payload, last.uuid)
    eq(JSON.parse(row.params).redirect_uri, REDIRECT)

    // 2. Over the limit per address: 429 and no sign request, for every flow, as page and as JSON
    for (const flow of FLOWS) {
      await limited('192.0.2.1', flow)
      await limited('192.0.2.1', flow, CLIENT_A, { json: true })
    }
    ok(logged.some(line => line === 'auth: start limit reached, per address ' + CLIENT_A), 'the refusal is logged, with the client')
    // The same address in other spellings, and another spelling of the client id: the same count
    await limited(' 192.0.2.1 ')
    await limited('::ffff:192.0.2.1')
    await limited('::FFFF:c000:201')
    await limited('192.0.2.1', IMPLICIT, CLIENT_A.toUpperCase())

    // 3. Another address, or another client from the same address: not affected
    await started('192.0.2.2')
    await started('192.0.2.1', IMPLICIT, CLIENT_B)
    await started('192.0.2.1', CODE_PKCE, CLIENT_B)
    await limited('192.0.2.1')

    // The form of a client without the Xaman sign-in creates no sign request: not counted, not limited
    const requests = sdk.created.length
    for (let i = 0; i < PER_ADDRESS + 5; i++) {
      const { res } = await start('192.0.2.1', CODE, CLIENT_FORM)
      eq(res.statusCode, 200)
      ok(res.kind === 'html' && /Granting Access/.test(res.value), 'the form')
    }
    eq(sdk.created.length, requests)
  }

  // IPv6: the addresses of one /64 network are one caller, another network is another caller
  {
    newWindow()
    for (let i = 0; i < PER_ADDRESS; i++) await started('2001:db8:1:2::' + (i + 1).toString(16))
    await limited('2001:db8:1:2:ffff:ffff:ffff:ffff')
    await limited('2001:DB8:1:2::1')
    await limited('2001:0db8:0001:0002:0000:0000:0000:0001')
    await started('2001:db8:1:3::1')
    await started('2001:db8:1::1')
  }

  // 4. The window slides: a start counts for 60 seconds from its own moment, not until the end of a fixed minute
  {
    newWindow()
    const t0 = clock.offset
    for (let i = 0; i < 20; i++) await started('192.0.2.10')
    clock.offset = t0 + 30 * SECOND
    for (let i = 0; i < 10; i++) await started('192.0.2.10')
    const first = await limited('192.0.2.10')
    ok(Number(first.headers['retry-after']) >= 29 && Number(first.headers['retry-after']) <= 30, 'room again when the oldest start leaves the window')

    // Requests over the limit are not counted: they do not make the wait longer
    clock.offset = t0 + 59 * SECOND
    for (let i = 0; i < 50; i++) await limited('192.0.2.10')

    clock.offset = t0 + 61 * SECOND // the 20 of t0 left the window, the 10 of t0 + 30 s still count
    for (let i = 0; i < 20; i++) await started('192.0.2.10')
    await limited('192.0.2.10')

    clock.offset = t0 + 89 * SECOND
    await limited('192.0.2.10')
    clock.offset = t0 + 91 * SECOND // the 10 of t0 + 30 s left the window
    for (let i = 0; i < 10; i++) await started('192.0.2.10')
    await limited('192.0.2.10')

    clock.offset = t0 + 200 * SECOND
    for (let i = 0; i < PER_ADDRESS; i++) await started('192.0.2.10')
    await limited('192.0.2.10')
  }

  // The limit per client, over all addresses: 600 starts from 40 addresses (15 each, far under the limit per
  // address), the next start of this client is refused from any address; another client is not affected
  {
    newWindow()
    const t0 = clock.offset
    const addresses = Array.from({ length: 40 }, (v, i) => '203.0.113.' + (i + 1))
    for (let i = 0; i < PER_CLIENT / 2; i++) await started(addresses[i % addresses.length], IMPLICIT, CLIENT_B)
    clock.offset = t0 + 20 * SECOND
    for (let i = 0; i < PER_CLIENT / 2; i++) await started(addresses[i % addresses.length], IMPLICIT, CLIENT_B)
    await limited('203.0.113.1', IMPLICIT, CLIENT_B)
    await limited('203.0.113.200', CODE_PKCE, CLIENT_B, { json: true })
    await limited(undefined, IMPLICIT, CLIENT_B)
    ok(logged.some(line => line === 'auth: start limit reached, per client ' + CLIENT_B))
    await started('203.0.113.1', IMPLICIT, CLIENT_A)

    clock.offset = t0 + 59 * SECOND
    await limited('203.0.113.200', IMPLICIT, CLIENT_B)
    clock.offset = t0 + 61 * SECOND // the first 300 left the window
    for (let i = 0; i < PER_CLIENT / 2; i++) await started(addresses[i % addresses.length], IMPLICIT, CLIENT_B)
    await limited('203.0.113.200', IMPLICIT, CLIENT_B)
  }

  // A request without a usable caller address: no count per address (those callers would all share one count),
  // the limit per client counts
  {
    newWindow()
    for (const address of [undefined, '', 'unknown', '192.0.2.1, 192.0.2.2', '999.1.1.1', '2001:db8::zz']) {
      for (let i = 0; i < PER_ADDRESS + 5; i++) await started(address)
    }
  }

  // 5. Memory is bounded: a key without a start in the window is removed
  {
    newWindow()
    for (let i = 0; i < 200; i++) await started('198.51.100.' + i, IMPLICIT, i % 2 ? CLIENT_A : CLIENT_B)
    eq(authStartLimit.size(), 202, '200 addresses + 2 clients')
    clock.offset += WINDOW + SECOND
    await started('198.51.100.1')
    eq(authStartLimit.size(), 2, 'only the keys of the last start are left')

    // The limiter on its own, with a clock of the test
    const small = createAuthStartLimit({ windowMs: 1000, maxPerAddress: 3, maxPerClient: 1000000, maxKeys: 50 })
    for (let i = 0; i < 5000; i++) small.take('address-' + i, 'client-' + (i % 500), 1000)
    ok(small.size() <= 100, 'never more keys than the maximum (per list): ' + small.size())
    // The key that goes at the maximum is the one that was not used for the longest time
    eq(small.take('address-4999', 'client-499', 1001).allowed, true)
    eq(small.take('address-4999', 'client-499', 1002).allowed, true)
    eq(small.take('address-4999', 'client-499', 1003).allowed, false, 'a new key is still counted at the maximum')
    eq(small.take('address-4999', 'client-499', 1003).limit, 'address')
    eq(small.take('address-4999', 'client-499', 1003).retryAfterMs, 997)
    small.take('address-x', 'client-x', 5000)
    eq(small.size(), 2, 'old keys are removed at the next start')

    // A list is never longer than its limit, also with many requests over the limit
    const one = createAuthStartLimit({ windowMs: 1000, maxPerAddress: 3, maxPerClient: 5, maxKeys: 50 })
    let allowed = 0
    for (let i = 0; i < 1000; i++) allowed += one.take('a', 'c', 1000 + Math.floor(i / 10)).allowed ? 1 : 0
    eq(allowed, 3)
    for (let i = 0; i < 1000; i++) allowed += one.take('address-' + i, 'c', 1500).allowed ? 1 : 0
    eq(allowed, 5, 'the limit per client')
    eq(one.size(), 4, '1 client + 3 addresses that had a start')
    // The clock of the host set back: a start "in the future" does not block
    eq(one.take('a', 'c', 500).allowed, true)
  }

  // The caller address of a request
  {
    const of = value => callerAddress({ headers: value === undefined ? {} : { 'cf-connecting-ip': value } })
    eq(of('192.0.2.7'), '192.0.2.7')
    eq(of('::ffff:192.0.2.7'), '192.0.2.7')
    eq(of('2001:db8:aa:bb:1:2:3:4'), '2001:db8:aa:bb::/64')
    eq(of('2001:DB8:AA:BB::1'), '2001:db8:aa:bb::/64')
    eq(of('2001:db8::1'), '2001:db8:0:0::/64')
    eq(of('::1'), '0:0:0:0::/64')
    eq(of('64:ff9b::192.0.2.7'), '64:ff9b:0:0::/64')
    for (const value of [undefined, '', ' ', 'x', '1.2.3', '1.2.3.4.5', '192.0.2.1, 192.0.2.2', ['192.0.2.1'], '2001:db8::1::2']) eq(of(value), undefined)
    eq(callerAddress({}), undefined)
    // Other headers and the address of the connection do not count
    eq(callerAddress({ headers: { 'x-forwarded-for': '192.0.2.7', 'x-real-ip': '192.0.2.7' }, ip: '192.0.2.7', socket: { remoteAddress: '192.0.2.7' } }), undefined)
  }

  // 6. A request with values that are not valid creates no sign request (and is not counted as a start)
  {
    newWindow()
    const valid = startQuery(CODE_PKCE)
    const MISSING = 'Required parameters are missing in the request.'
    const CLIENT_OR_URL = 'Invalid client/redirect URL.'
    const PKCE = 'Invalid code challenge or code challenge method.'
    const without = (query, key) => Object.keys(query).filter(k => k !== key).reduce((q, k) => ({ ...q, [k]: query[k] }), {})

    for (const flow of FLOWS) {
      const query = startQuery(flow)
      // Response type
      await refused(without(query, 'response_type'), 400, 'Grant type is invalid or missing.')
      await refused({ ...query, response_type: 'id_token' }, 400, 'Grant type is invalid or missing.')
      await refused({ ...query, response_type: ['code', 'token'] }, 400, 'Grant type is invalid or missing.')
      // Client
      await refused(without(query, 'client_id'), 400, MISSING)
      await refused({ ...query, client_id: [CLIENT_A] }, 400, MISSING)
      await refused({ ...query, client_id: { a: CLIENT_A } }, 400, MISSING)
      await refused({ ...query, client_id: '' }, 400, CLIENT_OR_URL)
      await refused({ ...query, client_id: crypto.randomUUID() }, 400, CLIENT_OR_URL)
      // Redirect URI
      await refused(without(query, 'redirect_uri'), 400, MISSING)
      await refused({ ...query, redirect_uri: [REDIRECT] }, 400, MISSING)
      await refused({ ...query, redirect_uri: '' }, 400, CLIENT_OR_URL)
      await refused({ ...query, redirect_uri: 'https://other.example/cb' }, 400, CLIENT_OR_URL)
      await refused({ ...query, redirect_uri: 'https://app.example.other.example/cb' }, 400, CLIENT_OR_URL)
    }

    // PKCE values (response type `code`)
    await refused(without(valid, 'code_challenge_method'), 400, MISSING)
    await refused(without(valid, 'code_challenge'), 400, MISSING)
    for (const code_challenge of ['a', challenge('v').slice(1), 'x'.repeat(129), challenge('v') + '=', challenge('v').slice(1) + '+', challenge('v').slice(1) + ' ', challenge('v').slice(1) + '/', [challenge('v')], [challenge('v'), challenge('w')], { a: challenge('v') }]) {
      await refused({ ...valid, code_challenge }, 400, PKCE)
    }
    for (const code_challenge_method of [['S256'], ['S256', 'plain'], { a: 'S256' }, 'S256 ', 'S 256', 'x'.repeat(33), 'S256\n']) {
      await refused({ ...valid, code_challenge_method }, 400, PKCE)
    }
    await refused({ ...valid, client_id: crypto.randomUUID() }, 400, CLIENT_OR_URL)

    // Nothing above was counted as a start of this caller. Valid PKCE values start the sign-in as before; the
    // implicit flow takes no PKCE values, so there they are not checked (as before).
    for (const pkce of [{}, { code_challenge: 'x'.repeat(43) }, { code_challenge: 'Aa0-._~'.repeat(18) + 'ab' }, { code_challenge_method: 'plain' }, { code_challenge_method: 's256' }, { code_challenge_method: 'SHA-256' }]) {
      const { res } = await call(auth, { query: { ...valid, ...pkce }, address: '198.51.100.99' })
      eq(res.kind, 'redirect', 'accepted: ' + JSON.stringify(pkce))
    }
    await started('198.51.100.99', { ...IMPLICIT, code_challenge: 'a', code_challenge_method: 'S256' })
    await started('198.51.100.99', { ...IMPLICIT, code_challenge: challenge('v'), code_challenge_method: 'S256' })
  }

  // 7. An error in a handler ends in an error answer, without the text of the error
  {
    newWindow()
    for (const flow of FLOWS) {
      // The datastore fails
      failQuery = true
      const requests = sdk.created.length
      const queryError = await call(auth, { query: startQuery(flow), json: true, address: '192.0.2.50' })
      const page = await call(auth, { query: startQuery(flow), address: '192.0.2.50' })
      failQuery = false
      eq(queryError.res.statusCode, 500)
      eq(queryError.res.value.error, 'server_error')
      eq(queryError.res.value.error_description, 'Unexpected error')
      ok(page.res.statusCode === 500 && page.res.kind === 'html' && /Unexpected error/.test(page.res.value) && !/SQL/.test(page.res.value), 'the error page, no datastore text')
      eq(sdk.created.length, requests, 'no sign request')

      // The sign-in start itself fails after the checks (here: the API gives no payload, and the error answer
      // for that cannot be written at first)
      sdk.noPayload = true
      const startError = await call(auth, { query: startQuery(flow), json: true, address: '192.0.2.50', brokenStatus: true })
      const noPayload = await call(auth, { query: startQuery(flow), json: true, address: '192.0.2.50' })
      sdk.noPayload = false
      eq(startError.res.statusCode, 500)
      eq(startError.res.value.error, 'server_error')
      eq(startError.res.value.error_description, 'Unexpected error')
      eq(noPayload.res.statusCode, 500, 'the API gives no payload: as before')
      eq(noPayload.res.value.error, 'xaman_api_final_err')
    }
    ok(logged.some(line => line === 'handleACPKCEAuthRequest error SQL text that must stay in the log'), 'the error text is in the log')
    ok(logged.some(line => line === 'handleImplicitAuthRequest error the answer could not be written'))

    // The sign-in route: an error before the handlers answer
    for (const json of [true, false]) {
      const { res } = await call(signin, { method: 'POST', query: { response_type: 'code' }, body: null, json })
      eq(res.statusCode, 500)
      if (json) eq(res.value.error_description, 'Unexpected error')
      else ok(res.kind === 'html' && /Unexpected error/.test(res.value) && !/Cannot read/.test(res.value), 'the error page, no error text')
    }
    ok(logged.some(line => /^signin error Cannot read/.test(line)))
  }

  await new Promise(resolve => setTimeout(resolve, 20))
  eq(unhandled.length, 0, 'no unhandled rejection: ' + unhandled.map(e => e?.message).join(' | '))
}

// The handlers of the process for errors that nothing caught (fn/processErrors.js, installed first in index.js),
// each in a process of its own. The service itself is not started.
const processErrors = () => {
  const run = code => spawnSync(process.execPath, ['-e', "require('./fn/processErrors')();" + code], { cwd: path.join(__dirname, '..'), encoding: 'utf8', timeout: 20000 })
  const lines = text => text.split('\n').filter(line => line !== '')

  // A rejection without a catch: one log line, the process keeps running and ends in the normal way
  const rejection = run("Promise.reject(new Error('rejected-1'));setTimeout(() => console.log('still running'), 100)")
  eq(rejection.status, 0, rejection.stderr)
  eq(rejection.stdout.trim(), 'still running')
  eq(lines(rejection.stderr).length, 1, 'one line: ' + rejection.stderr)
  ok(/^unhandledRejection: Error: rejected-1( \| at .+)?$/.test(rejection.stderr.trim()), rejection.stderr)
  ok(rejection.stderr.length < 1100)

  // A rejection with a value that is no error
  const value = run("Promise.reject('text-1');Promise.reject(null);setTimeout(() => console.log('still running'), 100)")
  eq(value.status, 0, value.stderr)
  eq(value.stdout.trim(), 'still running')
  assert.deepStrictEqual(lines(value.stderr), ['unhandledRejection: text-1', 'unhandledRejection: null'])
  n++

  // An error outside every handler: one log line, the process ends with code 1
  const thrown = run("setTimeout(() => { throw new Error('thrown-1') }, 10);setTimeout(() => console.log('still running'), 300)")
  eq(thrown.status, 1, thrown.stderr)
  eq(thrown.stdout.trim(), '', 'the process ended at the error')
  eq(lines(thrown.stderr).length, 1, 'one line: ' + thrown.stderr)
  ok(/^uncaughtException: Error: thrown-1( \| at .+)?$/.test(thrown.stderr.trim()), thrown.stderr)

  // index.js installs the handlers before anything else
  const index = require('fs').readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8')
  const firstCode = index.split('\n').filter(line => line.trim() !== '' && !line.trim().startsWith('//'))[0]
  eq(firstCode, "require('./fn/processErrors')()")
}

;(async () => {
  await suite()
  processErrors()
  realLog('authStepLimit:', n, 'checks OK')
})().catch(e => {
  realLog(e)
  process.exit(1)
})
