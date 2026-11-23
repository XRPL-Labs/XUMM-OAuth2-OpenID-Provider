// Run: node test/signinSingleUse.test.js
//
// The return step of the Xaman sign-in (/signin?t=&h=&c=&payload=), through the real route functions of
// functions.js. No config file, no database, no network: the config, the datastore and the Xaman SDK are fakes.
const assert = require('assert')
const crypto = require('crypto')
const Module = require('module')
const path = require('path')
const util = require('util')
const jwt = require('jsonwebtoken')

const CLIENT = '11111111-2222-4333-8444-555555555555'
const SECRET = crypto.randomBytes(32).toString('base64')
const REDIRECT = 'https://app.example/cb'
const ACCOUNT = 'rTestAccount1111111111111111111111'
const MINUTE = 60 * 1000

// ---- Fake config (the shape of config.sample.js), with a key pair made for this run
const fakeConfig = {
  port: 0,
  secret: SECRET,
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

// ---- Fake datastore: the methods of datastore.js that the handlers use, on arrays
let tables
let consumedDefault = 0 // the value of `consumed` in a new challenge row (the suite runs with 0 and with NULL)
let failUpsert = false
let failQuery = false

const sqlEqual = (a, b) => a !== null && a !== undefined && b !== null && b !== undefined &&
  String(typeof a === 'boolean' ? Number(a) : a) === String(typeof b === 'boolean' ? Number(b) : b)
const matches = (row, f) => {
  if (f.operator === '=') return sqlEqual(row[f.key], f.value)
  if (f.operator === '<=>') return (row[f.key] ?? null) === null || (f.value ?? null) === null ? (row[f.key] ?? null) === (f.value ?? null) : sqlEqual(row[f.key], f.value)
  throw new Error('fake datastore: operator ' + f.operator)
}

const turn = () => new Promise(resolve => setImmediate(resolve))

class FakeQuery {
  constructor (dataset) {
    this.dataset = dataset
    this.filters = []
  }

  filter (key, operator, value) {
    this.filters.push({ key, operator, value })
    return this
  }

  // A statement runs in one piece, but other requests get their turn before it (as with a real database): requests
  // at the same moment read the same row before one of them changes it
  async update (data) {
    await turn()
    const rows = tables[this.dataset].filter(r => this.filters.every(f => matches(r, f)))
    rows.forEach(r => Object.assign(r, data))
    return [{ affectedRows: rows.length }, undefined]
  }

  async get () {
    await turn()
    if (this.dataset === 'user') {
      const value = key => this.filters.filter(f => f.key === key).map(f => f.value)[0]
      return tables.user.filter(r => r.username === value('username')).filter(r => {
        // As datastore.js: a Xaman account has a password derived from the account, another user has its own
        const derived = crypto.createHash('sha256').update(r.username + SECRET).digest('hex')
        return r.xrpl_account ? value('password') === derived : value('password') === r.password
      }).map(r => ({ ...r }))
    }
    return tables[this.dataset].filter(r => this.filters.every(f => matches(r, f))).map(r => ({ ...r }))
  }
}

const datastore = {
  createQuery: dataset => new FakeQuery(dataset),
  async runQuery (query) {
    if (failQuery) throw new Error('SQL text that must stay in the log')
    return [await query.get()]
  },
  async updateQuery (query, data) {
    await query.update(data)
    return true
  },
  key: ([k, v]) => ({ [k]: v }),
  async upsert (data) {
    if (failUpsert) throw new Error('SQL text that must stay in the log')
    const row = {}
    Object.keys(data).forEach(k => Object.assign(row, data[k]))
    keepOutOfLog(row.authorization_code)
    keepOutOfLog(row.password)
    if (row.payload && typeof row.params === 'string') {
      const { __t, state, nonce, code_challenge: challenge } = JSON.parse(row.params)
      ;[__t, state, nonce, challenge].forEach(keepOutOfLog)
    }
    const put = (table, same, defaults) => {
      const found = tables[table].find(same)
      if (found) return Object.assign(found, row)
      tables[table].push({ ...defaults, ...row })
    }
    if (row.authorization_code) return put('grant', r => r.authorization_code === row.authorization_code, { fetched: 0 })
    if (row.xrpl_account) return put('user', r => r.username === row.username, {})
    if (row.payload) return put('xumm_challenge', r => r.payload === row.payload, { consumed: consumedDefault })
    throw new Error('Error, unknown dataset to upsert to')
  },
  transaction () {
    return {
      async run () { return this },
      async get (key) {
        if (key?.authorization_code) return tables.grant.filter(r => r.authorization_code === key.authorization_code && r.fetched === 0)
        throw new Error('Invalid dataset: transaction Get (key)')
      },
      async delete (key) { tables.grant.filter(r => r.authorization_code === key?.authorization_code).forEach(r => { r.fetched = 1 }) },
      async commit () {},
      async rollback () {}
    }
  }
}

// ---- Fake Xaman SDK: payload.create gives a new uuid, payload.get gives what the test stored for that uuid
const sdk = { created: [], results: {}, getCalls: 0 }
class XummSdk {
  constructor () {
    this.payload = {
      create: async payload => {
        const uuid = crypto.randomUUID()
        sdk.created.push({ uuid, return_url: payload.options.return_url.web.replace('{id}', uuid) })
        return { uuid, next: { always: 'https://xumm.test/sign/' + uuid } }
      },
      get: async uuid => {
        sdk.getCalls++
        await new Promise(resolve => setImmediate(resolve))
        const result = sdk.results[uuid]
        if (result instanceof Error) throw result
        return result === undefined ? null : result
      }
    }
  }
}

// For the one check of the real datastore.js (the statement it builds): a pool that records, no connection
const executed = []
const fakePool = {
  getConnection: async () => ({
    execute: async (sql, params) => {
      executed.push({ sql: sql.replace(/\s+/g, ' ').trim(), params })
      return [{ affectedRows: 1 }, undefined]
    },
    release () {}
  })
}

// Every require of the config, the datastore, the SDK or the database driver (by any module) gets the fake
const load = Module._load
Module._load = function (request) {
  if (/^\.\.?\/config$/.test(request)) return fakeConfig
  if (/^\.\.?\/datastore$/.test(request)) return { datastore, db: {} }
  if (request === 'xumm-sdk') return { XummSdk }
  if (request === 'mysql2/promise') return { createPool: () => fakePool }
  return load.apply(this, arguments)
}

const realLog = console.log
// The handlers log every step: the lines are kept, for the check of what a log line has (the end of the suite)
const logged = []
console.log = (...args) => { logged.push(args.map(a => typeof a === 'string' ? a : util.inspect(a, { depth: null, breakLength: Infinity })).join(' ')) }
// Values that are in no log line: every code, flow token and value of the /auth request that the suite stores
const notLogged = new Set(['client-secret-1', 'usertoken-1'])
const keepOutOfLog = value => { if (typeof value === 'string' && value.length >= 6) notLogged.add(value) }
const { auth, signin, token } = require('../functions')

// The clock of this host, for the tests of the time between the first use and a later one
const clock = { offset: 0 }
const realNow = Date.now
Date.now = () => realNow() + clock.offset

const unhandled = []
process.on('unhandledRejection', e => unhandled.push(e))

// ---- Request / response
let n = 0
const ok = (value, message) => { assert.ok(value, message); n++ }
const eq = (a, b, message) => { assert.strictEqual(a, b, message); n++ }

const call = async (route, { query = {}, body = {}, method = 'GET', json = false }) => {
  const req = { method, query, body, headers: {}, server2server: json }
  const res = { statusCode: 200, headersSent: false }
  const answered = new Promise(resolve => { res.end = resolve })
  const answer = (kind, value) => {
    assert.strictEqual(res.headersSent, false, 'one answer per request')
    Object.assign(res, { headersSent: true, kind, value })
    res.end()
  }
  res.status = code => { res.statusCode = code; return res }
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

const hashOf = t => crypto.createHash('sha256').update(t + CLIENT + SECRET).digest('hex').slice(0, 20)
const iso = ms => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z') // the format of the API: 2026-01-01T10:00:00Z

// A signed result. `apiClock`: the answer has expires_at + expires_in_seconds; `shift`: the clock of the API host is
// off by this much against the clock of this host.
const signed = (uuid, { account = ACCOUNT, resolvedAgo = 5000, apiClock = true, shift = 0, resolvedAt } = {}) => {
  const apiNow = Date.now() + shift
  return {
    meta: { uuid, signed: true, resolved: true },
    application: { uuidv4: CLIENT, name: 'Test app', issued_user_token: 'usertoken-1' },
    payload: apiClock ? { expires_at: iso(apiNow + 60 * MINUTE), expires_in_seconds: 3600 } : {},
    response: { account, resolved_at: resolvedAt === undefined ? iso(apiNow - resolvedAgo) : resolvedAt, environment_nodetype: 'MAINNET', environment_nodeuri: 'wss://node.test', environment_networkid: 0 }
  }
}
const rejected = uuid => ({ meta: { uuid, signed: false, resolved: true }, application: {}, payload: {}, response: { account: null, resolved_at: iso(Date.now()) } })

// The start of a flow through /auth: gives the payload uuid and the query of the return URL
const start = async (authQuery, result) => {
  const { res } = await call(auth, { query: { client_id: CLIENT, redirect_uri: REDIRECT, ...authQuery } })
  eq(res.kind, 'redirect', 'the flow start sends the user to the sign request')
  const { uuid, return_url } = sdk.created[sdk.created.length - 1]
  sdk.results[uuid] = result === undefined ? signed(uuid) : (typeof result === 'function' ? result(uuid) : result)
  const url = new URL(return_url)
  return { uuid, ret: { t: url.searchParams.get('t'), h: url.searchParams.get('h'), c: url.searchParams.get('c'), payload: url.searchParams.get('payload') } }
}
const IMPLICIT = { response_type: 'token', scope: 'XummPkce', state: 'state-1', nonce: 'nonce-1' } // the browser SDK
const IMPLICIT_REDIRECT = { response_type: 'token', scope: 'openid', state: 'state-1' }
const CODE_PKCE = verifier => ({ response_type: 'code', scope: 'openid', state: 'state-1', code_challenge: crypto.createHash('sha256').update(verifier).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''), code_challenge_method: 'S256' })
const CODE = { response_type: 'code', scope: 'openid', state: 'state-1' }

const pageOptions = res => {
  eq(res.kind, 'html', 'the answer is the return page')
  eq(res.statusCode, 200)
  return JSON.parse(decodeURIComponent(res.value.match(/<textarea id="pkce_options"[^>]*>([^<]*)</)[1]))
}
const location = res => {
  eq(res.kind, 'redirect', 'the answer is a redirect to the client')
  return new URL(res.value)
}
// The answer of a sign-in that gives no result: the OAuth2 error, no token and no code
const refusedPage = (res, description) => {
  const options = pageOptions(res)
  eq(options.error, 'access_denied')
  eq(options.error_description, description)
  eq(options.access_token, undefined, 'no token')
  eq(options.code, undefined, 'no code')
  eq(new URL(options.full_redirect_uri).origin + new URL(options.full_redirect_uri).pathname, REDIRECT)
  ok(!/access_token=|code=/.test(options.full_redirect_uri), 'no token or code in the redirect')
}
const refusedRedirect = (res, description) => {
  const url = location(res)
  eq(url.origin + url.pathname, REDIRECT)
  eq(url.searchParams.get('error'), 'access_denied')
  eq(url.searchParams.get('error_description'), description)
  eq(url.searchParams.get('state'), 'state-1')
  ok(!url.searchParams.has('access_token') && !url.searchParams.has('code') && !url.searchParams.has('authorization_code'), 'no token or code')
}
const USED = 'This sign in has already been used, please sign in again'
const EXPIRED = 'This sign in has expired, please sign in again'
const REJECTED = 'The XUMM sign in request has been rejected'
const challengeRow = uuid => tables.xumm_challenge.find(r => r.payload === uuid)
const storedParams = uuid => JSON.parse(challengeRow(uuid).params)

const newTables = () => ({
  client: [{ 'client-id': CLIENT, 'client-secret': 'client-secret-1', 'redirect-url': REDIRECT, 'implicit-enabled': 1, 'ac-enabled': 1, 'acpkce-enabled': 1, 'ropc-enabled': 1, 'signin-method': 'XUMMAPI' }],
  xumm_challenge: [],
  user: [{ id: 1, username: 'alice', password: 'alice-password', xrpl_account: 0 }],
  grant: []
})

const suite = async () => {
  tables = newTables()

  // 1. First use = the result. Implicit flow of the browser SDK (return page).
  {
    const { uuid, ret } = await start({ ...IMPLICIT, __t: 'from-the-auth-query', __used_at: String(Date.now() + 60 * MINUTE) })
    eq(storedParams(uuid).__t, ret.t, 'the flow token is stored with the challenge (a value of the /auth query does not replace it)')
    eq(hashOf(ret.t), ret.h)

    const first = await call(signin, { query: ret })
    const options = pageOptions(first.res)
    const claims = jwt.decode(options.access_token)
    eq(claims.sub, ACCOUNT)
    eq(claims.aud, CLIENT)
    eq(claims.payload_uuidv4, uuid)
    eq(claims.usertoken_uuidv4, 'usertoken-1')
    eq(options.state, 'state-1')
    eq(first.req.body.__t, undefined, 'the flow token is not part of the sign-in data')
    eq(first.req.body.__used_at, undefined, 'the time of the first use is not part of the sign-in data')
    eq(challengeRow(uuid).consumed, 11, 'the sign-in is marked as used once')
    const usedAt = storedParams(uuid).__used_at
    ok(typeof usedAt === 'number' && Math.abs(Date.now() - usedAt) < 5000, 'the time of the first use is stored (a value of the /auth query does not replace it)')
    eq(storedParams(uuid).__t, ret.t)

    // 2. Uses 2, 3 and 4 within 180 seconds after the first (the same return in another tab, a reload; GET and
    // POST) = the result once more, for the same flow, with the lifetime of the first
    for (const [use, seconds, method] of [[2, 1, 'GET'], [3, 90, 'POST'], [4, 179, 'GET']]) {
      clock.offset = seconds * 1000
      const again = await call(signin, { query: ret, method, body: method === 'POST' ? { response_type: 'code', code_challenge: 'x', username: 'rOtherAccount22222222222222222222' } : {} })
      assert.deepStrictEqual(jwt.decode(pageOptions(again.res).access_token), claims, 'use ' + use + ': the same data, issue time and end as the first token')
      n++
      eq(challengeRow(uuid).consumed, 10 + use)
      eq(storedParams(uuid).__used_at, usedAt, 'the time of the first use stays')
    }

    // The 5th use = refused, no token, and the API is not asked
    const calls = sdk.getCalls
    for (let i = 0; i < 3; i++) refusedPage((await call(signin, { query: ret })).res, USED)
    refusedPage((await call(signin, { query: ret, method: 'POST', body: { response_type: 'code', code_challenge: 'x' } })).res, USED)
    clock.offset = 0
    refusedPage((await call(signin, { query: ret })).res, USED)
    eq(sdk.getCalls, calls, 'a sign-in without a use left is refused before the API is asked')
    eq(challengeRow(uuid).consumed, 14)
  }

  // A use later than 180 seconds after the first = refused (as 2nd use, and as 3rd use after a 2nd in time)
  {
    const late = await start(IMPLICIT)
    eq(typeof pageOptions((await call(signin, { query: late.ret })).res).access_token, 'string')
    const mid = await start(IMPLICIT)
    eq(typeof pageOptions((await call(signin, { query: mid.ret })).res).access_token, 'string')
    clock.offset = 170 * 1000
    eq(typeof pageOptions((await call(signin, { query: mid.ret })).res).access_token, 'string', '2nd use at 170 s')
    const calls = sdk.getCalls
    clock.offset = 181 * 1000
    refusedPage((await call(signin, { query: late.ret })).res, USED)
    refusedPage((await call(signin, { query: late.ret, method: 'POST' })).res, USED)
    refusedPage((await call(signin, { query: mid.ret })).res, USED) // 11 s after its 2nd use: the first use counts
    clock.offset = 24 * 60 * MINUTE
    refusedPage((await call(signin, { query: late.ret })).res, USED)
    clock.offset = 0
    eq(sdk.getCalls, calls)
    eq(challengeRow(late.uuid).consumed, 11)
    eq(challengeRow(mid.uuid).consumed, 12)
  }

  // Implicit flow with a redirect (no return page): 4 uses (GET and POST), the 5th refused (redirect + state)
  {
    const { ret } = await start(IMPLICIT_REDIRECT)
    const url = location((await call(signin, { query: ret })).res)
    eq(url.origin + url.pathname, REDIRECT)
    eq(jwt.decode(url.searchParams.get('access_token')).sub, ACCOUNT)
    for (const method of ['POST', 'GET', 'POST']) {
      const again = location((await call(signin, { query: ret, method, body: { username: 'rOtherAccount22222222222222222222', scope: 'XummPkce', redirect_uri: 'https://other.example/cb' } })).res)
      eq(again.origin + again.pathname, REDIRECT)
      eq(again.searchParams.get('access_token'), url.searchParams.get('access_token'), 'the same token, nothing of the body')
    }
    refusedRedirect((await call(signin, { query: ret })).res, USED)
  }

  // Code flow with PKCE: a code per use (4 at most), all end at the same moment, each code gives the token once
  {
    const { uuid, ret } = await start(CODE_PKCE('verifier-1'))
    const grants = () => tables.grant.filter(g => g.xumm_payload === uuid)
    const codes = []
    for (const [use, seconds, method] of [[1, 0, 'GET'], [2, 30, 'POST'], [3, 100, 'GET'], [4, 175, 'POST']]) {
      clock.offset = seconds * 1000
      const url = location((await call(signin, { query: ret, method, body: method === 'POST' ? { code_challenge: 'other-challenge', client_id: 'other-client' } : {} })).res)
      ok(url.searchParams.get('code') && !codes.includes(url.searchParams.get('code')), 'use ' + use + ': a code')
      codes.push(url.searchParams.get('code'))
      eq(url.searchParams.get('state'), 'state-1')
      eq(grants().length, use)
      eq(grants()[use - 1].exp, grants()[0].exp, 'every code ends when the first ends')
      eq(grants()[use - 1].code_challenge, grants()[0].code_challenge)
      eq(grants()[use - 1].client_id, CLIENT)
      eq(grants()[use - 1].sub, ACCOUNT)
    }
    refusedRedirect((await call(signin, { query: ret })).res, USED)
    refusedRedirect((await call(signin, { query: ret, method: 'POST' })).res, USED)
    clock.offset = 0
    eq(grants().length, 4, '5th use: no code')

    for (const code of codes) {
      const body = { grant_type: 'authorization_code', client_id: CLIENT, code, redirect_uri: REDIRECT, code_verifier: 'verifier-1' }
      const tokenAnswer = await call(token, { method: 'POST', json: true, body: { ...body } })
      eq(tokenAnswer.res.statusCode, 200)
      eq(jwt.decode(tokenAnswer.res.value.access_token).sub, ACCOUNT)
      eq(jwt.decode(tokenAnswer.res.value.access_token).payload_uuidv4, uuid)
      eq((await call(token, { method: 'POST', json: true, body: { ...body } })).res.statusCode, 400, 'a code gives a token once')
    }
  }

  // Requests at the same moment: four get the result, a fifth (and more) does not
  for (const flow of [IMPLICIT, CODE]) {
    const hasResult = a => flow === CODE ? new URL(a.res.value).searchParams.has('code') : /access_token/.test(decodeURIComponent(a.res.value))
    const refused = a => flow === CODE ? refusedRedirect(a.res, USED) : refusedPage(a.res, USED)

    const four = await start(flow)
    const all = await Promise.all([1, 2, 3, 4].map(() => call(signin, { query: four.ret })))
    eq(all.filter(hasResult).length, 4, 'four requests at the same moment: all get the result')
    eq(challengeRow(four.uuid).consumed, 14)
    refused(await call(signin, { query: four.ret }))

    for (const count of [5, 9]) {
      const more = await start(flow)
      const answers = await Promise.all(Array.from({ length: count }, () => call(signin, { query: more.ret })))
      eq(answers.filter(hasResult).length, 4, count + ' requests at the same moment: four results')
      answers.filter(a => !hasResult(a)).forEach(refused)
      eq(challengeRow(more.uuid).consumed, 14)
      if (flow === CODE) eq(tables.grant.filter(g => g.xumm_payload === more.uuid).length, 4)
    }
  }

  // 3. A `t` that is not the one of this flow = refused (for every use), and no use is taken by it
  {
    const mine = await start(IMPLICIT)
    const other = await start(IMPLICIT) // a second flow of the same client: its t + h pair is valid for the client
    const wrong = async () => {
      for (const t of [other.ret.t, 'short', mine.ret.t + '0', mine.ret.t.slice(0, -1), mine.ret.t.toUpperCase() + 'x']) {
        const { res } = await call(signin, { query: { ...mine.ret, t, h: hashOf(t) } })
        eq(res.statusCode, 403, 'not the token of this flow: ' + t)
        ok(res.kind === 'html' && !/pkce_options|access_token/.test(res.value), 'the error page, no token')
      }
      const wrongHash = await call(signin, { query: { ...mine.ret, h: other.ret.h }, json: true })
      eq(wrongHash.res.statusCode, 403, 'as before: t + h do not belong together')
    }
    await wrong()
    eq(Number(challengeRow(mine.uuid).consumed || 0), 0)
    for (const use of [1, 2, 3, 4]) {
      eq(typeof pageOptions((await call(signin, { query: mine.ret })).res).access_token, 'string', 'the flow itself gets its result, use ' + use)
      await wrong()
      eq(challengeRow(mine.uuid).consumed, 10 + use)
    }
  }

  // 4. A row without a stored flow token (a flow that was open when this was released), and rows of before
  {
    const row = (uuid, result, consumed, extra) => {
      tables.xumm_challenge.push({ client: CLIENT, payload: uuid, params: JSON.stringify({ client_id: CLIENT, redirect_uri: REDIRECT, ...IMPLICIT, ...extra }), consumed })
      sdk.results[uuid] = result
      return { t: 'any-token-of-this-client', h: hashOf('any-token-of-this-client'), c: CLIENT, payload: uuid }
    }
    const fresh = crypto.randomUUID()
    const freshRet = row(fresh, signed(fresh, { resolvedAgo: 30 * 1000 }), consumedDefault)
    for (const use of [1, 2, 3, 4]) eq(jwt.decode(pageOptions((await call(signin, { query: freshRet })).res).access_token).sub, ACCOUNT, 'no stored token + fresh result: accepted, use ' + use)
    refusedPage((await call(signin, { query: freshRet })).res, USED)

    const old = crypto.randomUUID()
    refusedPage((await call(signin, { query: row(old, signed(old, { resolvedAgo: 11 * MINUTE }), consumedDefault) })).res, EXPIRED)

    // A row that was used before this release has consumed = 1: no use left. The same for every value that is not
    // "not used" or "used 1, 2 or 3 times", and for a count without a usable time of the first use.
    const calls = sdk.getCalls
    const now = Date.now()
    const noUseLeft = [
      [1], [1, { __t: 'any-token-of-this-client' }], [1, { __used_at: now }], ['1'], [true],
      [2, { __used_at: now }], [3, { __used_at: now }], [9, { __used_at: now }], [10, { __used_at: now }], [14, { __used_at: now }], [15, { __used_at: now }],
      [-1, { __used_at: now }], [-11, { __used_at: now }], [127, { __used_at: now }], [11.5, { __used_at: now }], [1763856000, { __used_at: now }], ['x', { __used_at: now }],
      [11], [12, { __used_at: null }], [13, { __used_at: 'x' }], [11, { __used_at: now - 181 * 1000 }], [13, { __used_at: now - 181 * 1000 }]
    ]
    for (const [consumed, extra] of noUseLeft) {
      const uuid = crypto.randomUUID()
      refusedPage((await call(signin, { query: row(uuid, signed(uuid), consumed, extra) })).res, USED)
      eq(challengeRow(uuid).consumed, consumed, 'the row is not changed')
    }
    eq(sdk.getCalls, calls)
    // The counterpart: a count with a time of the first use inside the 180 seconds has its uses left
    for (const [consumed, left] of [[11, 3], [12, 2], [13, 1], ['13', 1]]) {
      const uuid = crypto.randomUUID()
      const ret = row(uuid, signed(uuid), consumed, { __used_at: now - 170 * 1000 })
      for (let i = 0; i < left; i++) eq(typeof pageOptions((await call(signin, { query: ret })).res).access_token, 'string')
      refusedPage((await call(signin, { query: ret })).res, USED)
      eq(challengeRow(uuid).consumed, 14)
    }
  }

  // A later use is inside the 10 minutes after the sign request was resolved too
  {
    const { uuid, ret } = await start(IMPLICIT, id => signed(id, { resolvedAgo: 9 * MINUTE + 50 * 1000, apiClock: false }))
    eq(typeof pageOptions((await call(signin, { query: ret })).res).access_token, 'string')
    clock.offset = 20 * 1000
    refusedPage((await call(signin, { query: ret })).res, EXPIRED)
    clock.offset = 0
    eq(challengeRow(uuid).consumed, 11)
  }

  // 5. Resolved more than 10 minutes ago = refused
  {
    const cases = [
      // [the result, accepted?, what]
      [{ resolvedAgo: 9 * MINUTE }, true, '9 minutes'],
      [{ resolvedAgo: 11 * MINUTE }, false, '11 minutes'],
      [{ resolvedAgo: 26 * 60 * MINUTE }, false, 'a day'],
      [{ resolvedAgo: 9 * MINUTE, apiClock: false }, true, '9 minutes, by the clock of this host'],
      [{ resolvedAgo: 11 * MINUTE, apiClock: false }, false, '11 minutes, by the clock of this host'],
      [{ resolvedAgo: 9 * MINUTE, shift: 3 * 60 * MINUTE }, true, '9 minutes, the API clock is 3 hours ahead'],
      [{ resolvedAgo: 11 * MINUTE, shift: 3 * 60 * MINUTE }, false, '11 minutes, the API clock is 3 hours ahead'],
      [{ resolvedAgo: 9 * MINUTE, shift: -3 * 60 * MINUTE }, true, '9 minutes, the API clock is 3 hours behind'],
      [{ resolvedAgo: 11 * MINUTE, shift: -3 * 60 * MINUTE }, false, '11 minutes, the API clock is 3 hours behind'],
      [{ resolvedAt: null }, false, 'no resolve time'],
      [{ resolvedAt: 'not a date' }, false, 'a resolve time that is not a date']
    ]
    for (const [result, accepted, what] of cases) {
      const { uuid, ret } = await start(IMPLICIT, id => signed(id, result))
      const { res } = await call(signin, { query: ret })
      if (accepted) eq(typeof pageOptions(res).access_token, 'string', 'accepted: ' + what)
      else refusedPage(res, EXPIRED)
      eq(Number(challengeRow(uuid).consumed || 0), accepted ? 11 : 0, what)
    }
    const { ret } = await start(CODE, id => signed(id, { resolvedAgo: 11 * MINUTE }))
    refusedRedirect((await call(signin, { query: ret })).res, EXPIRED)
    eq(tables.grant.filter(g => g.xumm_payload === ret.payload).length, 0)
  }

  // 6. The sign-in data is the stored challenge + the API result: the body and the query of the return request
  // change nothing (username / account, password, client, redirect URI, scope, state, nonce, response type, code
  // challenge, payload, user token, app name, network)
  const hostile = {
    username: 'rOtherAccount22222222222222222222', password: 'x', client_id: 'other-client', redirect_uri: 'https://other.example/cb',
    scope: 'other-scope', state: 'other-state', nonce: 'other-nonce', response_type: 'code', code_challenge: 'other-challenge', code_challenge_method: 'S256',
    xumm_payload: 'other-payload', xumm_app_usertoken: 'other-usertoken', xumm_app_name: 'Other app', xumm_app_uuid: 'other-app',
    xumm_network_type: 'OTHER', xumm_network_endpoint: 'wss://other.example', xumm_network_id: '99', sub: 'other', __t: 'other'
  }
  {
    // Implicit flow: stays implicit, for the stored client / redirect URI / scope / state, as the account that signed
    const { uuid, ret } = await start(IMPLICIT)
    const { req, res } = await call(signin, { method: 'POST', query: { ...ret, ...hostile, ...ret }, body: { ...hostile } })
    const options = pageOptions(res)
    const claims = jwt.decode(options.access_token)
    eq(claims.sub, ACCOUNT)
    eq(claims.client_id, CLIENT)
    eq(claims.aud, CLIENT)
    eq(claims.app_uuidv4, CLIENT)
    eq(claims.scope, 'XummPkce')
    eq(claims.state, 'state-1')
    eq(claims.nonce, 'nonce-1')
    eq(claims.payload_uuidv4, uuid)
    eq(claims.usertoken_uuidv4, 'usertoken-1')
    eq(claims.app_name, 'Test app')
    eq(claims.network_type, 'MAINNET')
    eq(claims.network_endpoint, 'wss://node.test')
    eq(claims.network_id, '0')
    eq(claims.email, CLIENT + '+' + ACCOUNT + '@oauth2.test')
    eq(options.redirect_uri, REDIRECT)
    eq(new URL(options.full_redirect_uri).origin + new URL(options.full_redirect_uri).pathname, REDIRECT)
    eq(options.code, undefined, 'no code: the response type of the flow start counts')
    eq(tables.grant.filter(g => g.xumm_payload === uuid || g.xumm_payload === 'other-payload').length, 0)
    Object.keys(hostile).filter(k => !['client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'response_type', 'username', 'password', 'xumm_payload', 'xumm_app_usertoken', 'xumm_app_name', 'xumm_app_uuid', 'xumm_network_type', 'xumm_network_endpoint', 'xumm_network_id'].includes(k))
      .forEach(k => eq(req.body[k], undefined, 'not in the sign-in data: ' + k))
    ok(!JSON.stringify(req.body).includes('other'), 'nothing of the request body is in the sign-in data')
    eq(tables.user.filter(u => u.username === hostile.username).length, 0)
  }
  {
    // Code flow without PKCE: a posted code challenge does not turn it into a PKCE grant
    const { uuid, ret } = await start(CODE)
    const url = location((await call(signin, { method: 'POST', query: ret, body: { ...hostile, response_type: 'token' } })).res)
    eq(url.origin + url.pathname, REDIRECT)
    eq(url.searchParams.get('state'), 'state-1')
    eq(url.searchParams.get('access_token'), null, 'no token: the response type of the flow start counts')
    const grants = tables.grant.filter(g => g.xumm_payload === uuid)
    eq(grants.length, 1)
    eq(grants[0].authorization_code, url.searchParams.get('code'))
    eq(grants[0].sub, ACCOUNT)
    eq(grants[0].client_id, CLIENT)
    eq(grants[0].redirect_url, REDIRECT)
    eq(grants[0].scope, 'openid')
    eq(grants[0].code_challenge, undefined)
    eq(grants[0].xumm_app_usertoken, 'usertoken-1')
    ok(!JSON.stringify(grants[0]).includes('other'), 'nothing of the request body is in the grant')
    const noSecret = await call(token, { method: 'POST', json: true, body: { grant_type: 'authorization_code', client_id: CLIENT, code: grants[0].authorization_code, redirect_uri: REDIRECT, client_secret: 'wrong' } })
    eq(noSecret.res.statusCode, 400)
    const withSecret = await call(token, { method: 'POST', json: true, body: { grant_type: 'authorization_code', client_id: CLIENT, code: grants[0].authorization_code, redirect_uri: REDIRECT, client_secret: 'client-secret-1' } })
    eq(jwt.decode(withSecret.res.value.access_token).sub, ACCOUNT)
  }

  // 7. A rejected sign request = as before (and it can be asked again: nothing is used up)
  {
    const page = await start(IMPLICIT, rejected)
    for (let i = 0; i < 2; i++) refusedPage((await call(signin, { query: page.ret })).res, REJECTED)
    eq(Number(challengeRow(page.uuid).consumed || 0), 0)
    const redirect = await start(CODE, rejected)
    refusedRedirect((await call(signin, { query: redirect.ret })).res, REJECTED)
    // Signed, but the answer has no account
    const noAccount = await start(IMPLICIT, id => signed(id, { account: null }))
    refusedPage((await call(signin, { query: noAccount.ret })).res, REJECTED)
  }

  // 8. An error of the API or of the datastore = the error answer, and the sign-in is not used up by it
  {
    const { uuid, ret } = await start(IMPLICIT, new Error('API is down'))
    const thrown = await call(signin, { query: ret, json: true })
    eq(thrown.res.statusCode, 500)
    eq(thrown.res.value.error, 'handle_signin_fatal')
    const html = await call(signin, { query: ret })
    ok(html.res.statusCode === 500 && html.res.kind === 'html' && !/pkce_options/.test(html.res.value), 'the error page')

    sdk.results[uuid] = null // the SDK gives null when the API gave no payload
    refusedPage((await call(signin, { query: ret })).res, REJECTED)

    sdk.results[uuid] = signed(uuid)
    failUpsert = true
    eq((await call(signin, { query: ret, json: true })).res.statusCode, 500)
    failUpsert = false
    eq(Number(challengeRow(uuid).consumed || 0), 0, 'an error before the result does not use up the sign-in')
    eq(typeof pageOptions((await call(signin, { query: ret })).res).access_token, 'string', 'the next request gets the result')

    // The flow start: no row stored = the error page, the user is not sent on
    failUpsert = true
    const noRow = await call(auth, { query: { client_id: CLIENT, redirect_uri: REDIRECT, ...IMPLICIT }, json: true })
    failUpsert = false
    eq(noRow.res.statusCode, 500)
    eq(noRow.res.value.error, 'xaman_signin_store_err')
    ok(!JSON.stringify(noRow.res.value).includes('SQL'), 'no datastore text in the answer')

    // Unknown payload / a payload of another client: as before
    eq((await call(signin, { query: { ...ret, payload: crypto.randomUUID() }, json: true })).res.value.error, 'xaman_signin_redir_err')
  }

  // 9. The user name + password form (no payload in the query): untouched, the body is the sign-in data
  {
    const form = { response_type: 'token', username: 'alice', password: 'alice-password', client_id: CLIENT, redirect_uri: REDIRECT, state: 'form-state' }
    const url = location((await call(signin, { method: 'POST', body: { ...form } })).res)
    eq(jwt.decode(url.searchParams.get('access_token')).sub, 'alice')
    eq(url.searchParams.get('state'), 'form-state')

    // Errors of the sign-in handlers get an answer (were: no answer, an unhandled rejection)
    for (const body of [{ ...form, password: 'wrong' }, { ...form, password: 'wrong', response_type: 'code', code_challenge: 'x' }, { ...form, redirect_uri: 'https://other.example/cb' }, { ...form, redirect_uri: 'https://other.example/cb', response_type: 'code', code_challenge: 'x' }]) {
      const { res } = await call(signin, { method: 'POST', body, json: true })
      eq(res.statusCode, 400)
      ok(['Invalid user credentials.', 'Invalid client and/or redirect URL.'].includes(res.value.error_description))
    }
    failUpsert = true
    const storeError = await call(signin, { method: 'POST', json: true, body: { ...form, response_type: 'code', code_challenge: 'x' } })
    failUpsert = false
    eq(storeError.res.statusCode, 500)
    eq(storeError.res.value.error_description, 'Unexpected error')

    // Token handlers: an unknown error gets an answer without its text
    for (const body of [
      { grant_type: 'authorization_code', client_id: CLIENT, code: '', redirect_uri: REDIRECT, code_verifier: 'v' },
      { grant_type: 'authorization_code', client_id: CLIENT, code: '', redirect_uri: REDIRECT, client_secret: 'client-secret-1' }
    ]) {
      const { res } = await call(token, { method: 'POST', body, json: true })
      eq(res.statusCode, 500)
      eq(res.value.error, 'server_error')
      eq(res.value.error_description, 'Unexpected error')
    }
    failQuery = true
    const queryError = await call(token, { method: 'POST', json: true, body: { grant_type: 'password', username: 'alice', password: 'alice-password', client_id: CLIENT, client_secret: 'client-secret-1' } })
    failQuery = false
    eq(queryError.res.statusCode, 500)
    eq(queryError.res.value.error_description, 'Unexpected error')
    // Known errors: as before
    const wrongCode = await call(token, { method: 'POST', json: true, body: { grant_type: 'authorization_code', client_id: CLIENT, code: 'unknown', redirect_uri: REDIRECT, code_verifier: 'v' } })
    eq(wrongCode.res.statusCode, 400)
    eq(wrongCode.res.value.error_description, 'Invalid authorization code.')
  }

  await new Promise(resolve => setTimeout(resolve, 20))
  eq(unhandled.length, 0, 'no unhandled rejection: ' + unhandled.map(e => e?.message).join(' | '))

  // The log of all of the above. The return step has one line with the ids of the flow (client, sign request). No
  // line has a code, a flow token, a token, a password value or a value of the /auth request (state, nonce, code
  // challenge).
  ok(logged.some(line => /^Sign in return 11111111-2222-4333-8444-555555555555 [0-9a-f-]{36}$/.test(line)), 'the return step is logged with its ids')
  ok(notLogged.size > 20, 'values to look for: ' + notLogged.size)
  for (const value of notLogged) {
    const line = logged.find(l => l.includes(value))
    eq(line, undefined, 'a stored value is in a log line: ' + String(line).slice(0, 80))
  }
  ok(!logged.some(line => /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./.test(line)), 'no token in a log line')
  ok(!logged.some(line => /challengeData|code_challenge|nonce/.test(line)), 'no value of the /auth request in a log line')
}

// The statements that take a use, as the real datastore.js builds them: ONE update per use, with the condition in
// it. The reads of the request come from the fake rows, the update goes through the query class of datastore.js
// (its pool is the recording one above, so the fake row is not changed by it).
const realDatastoreStatement = async () => {
  const real = load.call(Module, path.join(__dirname, '..', 'datastore.js'), module, false).datastore
  const fakeCreateQuery = datastore.createQuery
  datastore.createQuery = dataset => {
    const query = new FakeQuery(dataset)
    query.update = data => query.filters.reduce((q, f) => q.filter(f.key, f.operator, f.value), real.createQuery(dataset)).update(data)
    return query
  }
  const params = { client_id: CLIENT, redirect_uri: REDIRECT, ...IMPLICIT, __t: 'token-1' }
  const use = async row => {
    tables = newTables()
    tables.xumm_challenge.push({ client: CLIENT, payload: 'payload-1', ...row })
    sdk.results['payload-1'] = signed('payload-1')
    executed.length = 0
    const { res } = await call(signin, { query: { t: 'token-1', h: hashOf('token-1'), c: CLIENT, payload: 'payload-1' } })
    eq(typeof pageOptions(res).access_token, 'string')
    eq(executed.length, 1, 'one statement')
    return executed[0]
  }

  // First use: NULL or 0 -> 11, with the time of this use in params
  for (const stored of [0, null]) {
    const before = Date.now()
    const first = await use({ consumed: stored, params: JSON.stringify(params) })
    eq(first.sql, 'UPDATE xumm_challenges SET `consumed` = ?, `params` = ? WHERE `payload` = ? AND `client` = ? AND `consumed` <=> ?')
    const { __used_at: usedAt, ...rest } = JSON.parse(first.params[1])
    ok(usedAt >= before && usedAt <= Date.now())
    assert.deepStrictEqual(rest, params)
    assert.deepStrictEqual([first.params[0], ...first.params.slice(2)], [11, 'payload-1', CLIENT, stored])
    n += 2
  }

  // Uses 2, 3 and 4: 11 -> 12 -> 13 -> 14, the count only
  for (const stored of [11, 12, 13]) {
    const later = await use({ consumed: stored, params: JSON.stringify({ ...params, __used_at: Date.now() - 1000 }) })
    eq(later.sql, 'UPDATE xumm_challenges SET `consumed` = ? WHERE `payload` = ? AND `client` = ? AND `consumed` <=> ?')
    assert.deepStrictEqual(later.params, [stored + 1, 'payload-1', CLIENT, stored])
    n++
  }

  datastore.createQuery = fakeCreateQuery
}

;(async () => {
  await realDatastoreStatement()
  for (const value of [0, null]) { // `consumed` of a new row: 0 or NULL, both mean "not used"
    consumedDefault = value
    await suite()
  }
  realLog('signinSingleUse:', n, 'checks OK')
})().catch(e => {
  realLog(e)
  process.exit(1)
})
