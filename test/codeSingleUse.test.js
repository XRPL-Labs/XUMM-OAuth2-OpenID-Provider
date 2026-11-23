// Run: node test/codeSingleUse.test.js
//
// The token step (/token, grant type authorization_code): an authorization code is used once, also when requests
// have the same code at the same moment. Through the real route function of functions.js, the real handlers,
// fn/verifyAuthorizationCode.js and datastore.js. No config file, no database, no network: the config is a fake,
// the database pool is a fake that runs the statements of datastore.js on arrays (with their conditions).
const assert = require('assert')
const crypto = require('crypto')
const Module = require('module')
const util = require('util')
const jwt = require('jsonwebtoken')

const CLIENT = '11111111-2222-4333-8444-555555555555'
const OTHER_CLIENT = '99999999-2222-4333-8444-555555555555'
const CLIENT_SECRET = 'SECRETMARK-' + crypto.randomBytes(8).toString('hex')
const REDIRECT = 'https://app.example/cb'
const ACCOUNT = 'rTestAccount1111111111111111111111'
const VERIFIER = 'VERIFIERMARK-' + crypto.randomBytes(32).toString('hex')
const challengeOf = verifier => crypto.createHash('sha256').update(verifier).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

const keyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' }
})
const fakeConfig = {
  port: 0,
  secret: crypto.randomBytes(32).toString('base64'),
  db: { uri: 'mysql://none' },
  maildomain: 'oauth2.test',
  jwt: { ISSUER: 'https://oauth2.test', JWT_LIFE_SPAN: 7200, CODE_LIFE_SPAN: 600, PRIVATE_KEY: keyPair.privateKey },
  openid: { discovery: { issuer: 'https://oauth2.test' }, certs: [] }
}

// ---- Fake database pool. A statement runs in one piece (as in a database), but before it other requests get
// their turn, a different number of turns per statement: requests at the same moment read the same row before one
// of them changes it. The numbers come from a fixed seed: every run has the same order.
let seed = 20261123
const random = max => {
  seed = (seed * 1103515245 + 12345) % 2147483648
  return Math.floor(seed / 65536) % max
}
const turn = () => new Promise(resolve => setImmediate(resolve))
const turns = async () => { for (let i = random(4); i > 0; i--) await turn() }

let tables
const pool = { taken: 0, released: 0, failConnection: null, failStatement: null, afterStatement: null }
const executed = []

const sqlEqual = (a, b) => a !== null && a !== undefined && b !== null && b !== undefined &&
  String(typeof a === 'boolean' ? Number(a) : a) === String(typeof b === 'boolean' ? Number(b) : b)
// "`a` = ? AND `b` > ?" with its values: the test of a row
const where = (clause, values) => {
  const conditions = clause.split(' AND ').map(part => {
    const m = part.match(/^`([^`]+)` (=|>) \?$/)
    if (!m) throw new Error('fake pool: condition ' + part)
    return { key: m[1], operator: m[2] }
  })
  assert.strictEqual(conditions.length, values.length, 'a value for every condition')
  return row => conditions.every((c, i) => c.operator === '=' ? sqlEqual(row[c.key], values[i]) : (row[c.key] ?? null) !== null && Number(row[c.key]) > Number(values[i]))
}
const run = (sql, params) => {
  let m
  if ((m = sql.match(/^SELECT \* FROM (\w+) WHERE (.+)$/))) {
    return [tables[m[1]].filter(where(m[2], params)).map(row => ({ ...row })), []]
  }
  if ((m = sql.match(/^UPDATE (\w+) SET (.+?) WHERE (.+)$/))) {
    const fields = m[2].split(', ').map(part => part.match(/^`(\w+)` = \?$/)[1])
    const rows = tables[m[1]].filter(where(m[3], params.slice(fields.length)))
    rows.forEach(row => fields.forEach((field, i) => { row[field] = params[i] }))
    return [{ affectedRows: rows.length }, undefined]
  }
  throw new Error('fake pool: statement ' + sql)
}
const fakePool = {
  getConnection: async () => {
    await turns()
    if (pool.failConnection) throw pool.failConnection
    pool.taken++
    return {
      execute: async (text, params) => {
        const sql = text.replace(/\s+/g, ' ').trim()
        await turns()
        executed.push({ sql, params })
        if (pool.failStatement && pool.failStatement.test.test(sql)) throw pool.failStatement.error
        const result = run(sql, params)
        if (pool.afterStatement) pool.afterStatement(sql)
        return result
      },
      release () { pool.released++ }
    }
  }
}

const load = Module._load
Module._load = function (request) {
  if (/^\.\.?\/config$/.test(request)) return fakeConfig
  if (request === 'mysql2/promise') return { createPool: () => fakePool }
  return load.apply(this, arguments)
}

const realLog = console.log
const logged = []
console.log = (...args) => { logged.push(args.map(a => typeof a === 'string' ? a : util.inspect(a, { depth: null, breakLength: Infinity })).join(' ')) }

const { token } = require('../functions')

const clock = { offset: 0 }
const realNow = Date.now
Date.now = () => realNow() + clock.offset

const unhandled = []
process.on('unhandledRejection', e => unhandled.push(e))

// ---- Request / response
let n = 0
const ok = (value, message) => { assert.ok(value, message); n++ }
const eq = (a, b, message) => { assert.strictEqual(a, b, message); n++ }
const same = (a, b, message) => { assert.deepStrictEqual(a, b, message); n++ }

const call = async (body, headers = {}) => {
  const req = { method: 'POST', query: {}, body: { ...body }, headers, server2server: true }
  const res = { statusCode: 200, headersSent: false }
  const answered = new Promise(resolve => { res.end = resolve })
  const answer = value => {
    assert.strictEqual(res.headersSent, false, 'one answer per request')
    Object.assign(res, { headersSent: true, value })
    res.end()
  }
  res.status = code => { res.statusCode = code; return res }
  res.json = data => { answer(data); return res }
  res.send = html => { answer(String(html)); return res }
  token(req, res)
  let timer
  await Promise.race([answered, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('no answer to the request')), 3000) })])
  clearTimeout(timer)
  await turn()
  return res
}

// ---- Rows
let codes = 0
const newTables = () => ({
  clients: [
    { 'client-id': CLIENT, 'client-secret': CLIENT_SECRET, 'redirect-url': REDIRECT, 'implicit-enabled': 1, 'ac-enabled': 1, 'acpkce-enabled': 1 },
    { 'client-id': OTHER_CLIENT, 'client-secret': 'other-secret', 'redirect-url': REDIRECT, 'implicit-enabled': 1, 'ac-enabled': 1, 'acpkce-enabled': 1 }
  ],
  grants: []
})
// A new code as the sign-in step stores it (`fetched` 0 is the default of the column). `pkce`: with a challenge.
const grant = (pkce, values = {}) => {
  const row = {
    authorization_code: 'CODEMARK-' + (++codes) + '-' + crypto.randomBytes(12).toString('hex'),
    client_id: CLIENT,
    redirect_url: REDIRECT,
    exp: Date.now() + 600 * 1000,
    code_challenge: pkce ? challengeOf(VERIFIER) : null,
    scope: 'openid',
    nonce: 'nonce-1',
    sub: ACCOUNT,
    xumm_payload: 'payload-' + codes,
    fetched: 0,
    ...values
  }
  tables.grants.push(row)
  return row
}

// The two flows: with a client secret (AC), with a code verifier and no secret (AC + PKCE, the browser SDK)
const AC = row => ({ grant_type: 'authorization_code', client_id: CLIENT, client_secret: CLIENT_SECRET, code: row.authorization_code, redirect_uri: REDIRECT })
const PKCE = row => ({ grant_type: 'authorization_code', client_id: CLIENT, code: row.authorization_code, redirect_uri: REDIRECT, code_verifier: VERIFIER })
const flows = [['AC', false, AC], ['AC + PKCE', true, PKCE]]

const tokens = (res, row, message) => {
  eq(res.statusCode, 200, message)
  const claims = jwt.verify(res.value.access_token, keyPair.publicKey, { algorithms: ['RS256'], issuer: fakeConfig.jwt.ISSUER })
  eq(claims.sub, ACCOUNT)
  eq(claims.aud, CLIENT)
  eq(claims.client_id, CLIENT)
  eq(claims.payload_uuidv4, row.xumm_payload, 'the token is the one of this code')
  eq(claims.nonce, 'nonce-1')
  eq(res.value.id_token, res.value.access_token)
  eq(res.value.token_type, 'bearer')
  eq(res.value.scope, 'openid')
}
const refused = (res, description, message) => {
  eq(res.statusCode, 400, message)
  same(res.value, { error: 'access_denied', error_description: description }, message)
}
const INVALID = 'Invalid authorization code.'
const serverError = (res, message) => {
  eq(res.statusCode, 500, message)
  same(res.value, { error: 'server_error', error_description: 'Unexpected error' }, message)
}

const suite = async () => {
  tables = newTables()

  // 1. The normal flow: the code gives the tokens once. Later the same code gets the answer of an unknown code.
  for (const [name, pkce, body] of flows) {
    const row = grant(pkce)
    tokens(await call(body(row)), row, name)
    eq(row.fetched, 1, 'the code is used')

    const again = await call(body(row))
    const unknown = await call({ ...body(row), code: 'CODEMARK-unknown' })
    refused(again, INVALID, name + ': the second request')
    same(again.value, unknown.value, 'the same answer as for a code that does not exist')
    eq(again.statusCode, unknown.statusCode)

    // The other name of the parameter, and the client credentials in the Authorization header
    const named = grant(pkce)
    const { code, ...rest } = body(named)
    tokens(await call({ ...rest, authorization_code: code }), named, name + ': authorization_code')
  }
  {
    const row = grant(false)
    const { client_id: id, client_secret: secret, ...rest } = AC(row)
    tokens(await call(rest, { authorization: 'Basic ' + Buffer.from(id + ':' + secret).toString('base64') }), row, 'Basic')
    // AC + PKCE of a client with a secret
    const withSecret = grant(true)
    tokens(await call({ ...PKCE(withSecret), client_secret: CLIENT_SECRET }), withSecret, 'PKCE with a client secret')
  }

  // 2. The statements of a token request, as datastore.js builds them: one read, then ONE update with the
  // conditions in it
  {
    const row = grant(true)
    executed.length = 0
    const before = Date.now()
    tokens(await call(PKCE(row)), row)
    same(executed.map(e => e.sql), [
      'SELECT * FROM clients WHERE `client-id` = ? AND `acpkce-enabled` = ? AND `implicit-enabled` = ?',
      'SELECT * FROM grants WHERE `authorization_code` = ? AND `fetched` = ?',
      'UPDATE grants SET `fetched` = ? WHERE `authorization_code` = ? AND `fetched` = ? AND `exp` > ?'
    ])
    same(executed[1].params, [row.authorization_code, 0])
    same(executed[2].params.slice(0, 3), [1, row.authorization_code, 0])
    ok(executed[2].params[3] >= before && executed[2].params[3] <= Date.now(), 'the end time is compared with this moment')
  }

  // 3. Requests with the same code at the same moment: exactly one gets the tokens, the others the answer of an
  // unknown code. Many rounds, each with another order of the statements of the requests.
  for (const [name, pkce, body] of flows) {
    let firstWon = 0
    for (let round = 0; round < 400; round++) {
      const row = grant(pkce)
      const count = 2 + (round % 4)
      const answers = await Promise.all(Array.from({ length: count }, () => call(body(row))))
      const withTokens = answers.filter(res => res.statusCode === 200)
      assert.strictEqual(withTokens.length, 1, name + ', round ' + round + ': ' + count + ' requests, ' + withTokens.length + ' with tokens')
      assert.strictEqual(jwt.decode(withTokens[0].value.access_token).payload_uuidv4, row.xumm_payload)
      for (const res of answers.filter(res => res.statusCode !== 200)) {
        assert.strictEqual(res.statusCode, 400)
        assert.deepStrictEqual(res.value, { error: 'access_denied', error_description: INVALID })
      }
      assert.strictEqual(row.fetched, 1)
      if (answers[0].statusCode === 200) firstWon++
      n++
    }
    ok(firstWon > 20 && firstWon < 380, name + ': the order of the requests differs per round (the first request got the tokens in ' + firstWon + ' of 400)')
    ok(logged.includes('verifyAuthorizationCode: the code was used by another request at the same moment ' + CLIENT + ' ' + ACCOUNT), 'the log has a line for it, with the ids of the client and the account')
  }

  // The same, with a request that does not fit the code at the same moment (wrong verifier): one token at most
  {
    let good = 0
    for (let round = 0; round < 200; round++) {
      const row = grant(true)
      const answers = await Promise.all([
        call(PKCE(row)),
        call({ ...PKCE(row), code_verifier: 'VERIFIERMARK-other' }),
        call(PKCE(row))
      ])
      const withTokens = answers.filter(res => res.statusCode === 200)
      assert.ok(withTokens.length <= 1, 'round ' + round + ': ' + withTokens.length + ' with tokens')
      assert.strictEqual(answers[1].statusCode, 400)
      assert.strictEqual(row.fetched, 1)
      good += withTokens.length
      n++
    }
    ok(good > 0 && good < 200, 'the request with the wrong verifier was first in some rounds (' + (200 - good) + ' of 200)')
  }

  // 4. A request that does not fit the code: refused with its reason (as before), and the code is used (one attempt
  // per code): the right request after it gets the answer of an unknown code
  for (const [name, pkce, body, change, reason] of [
    ['wrong verifier', true, PKCE, { code_verifier: 'VERIFIERMARK-other' }, 'Code verifier does not match code challenge.'],
    ['verifier that is not text', true, PKCE, { code_verifier: ['a', 'b'] }, 'Code verifier does not match code challenge.'],
    ['verifier for a code without a challenge', false, PKCE, {}, 'Code verifier does not match code challenge.'],
    ['other client', false, AC, { client_id: OTHER_CLIENT, client_secret: 'other-secret' }, 'Client ID does not match the record.'],
    ['other client (PKCE)', true, PKCE, { client_id: OTHER_CLIENT }, 'Client ID does not match the record.'],
    ['other redirect URI', false, AC, { redirect_uri: 'https://other.example/cb' }, 'Redirect URL does not match the record.'],
    ['other redirect URI (PKCE)', true, PKCE, { redirect_uri: 'https://app.example/other' }, 'Redirect URL does not match the record.'],
    ['redirect URI that is not text', false, AC, { redirect_uri: ['https://app.example/cb', 'x'] }, 'Redirect URL does not match the record.']
  ]) {
    const row = grant(pkce)
    refused(await call({ ...body(row), ...change }), reason, name)
    eq(row.fetched, 1, name + ': the code is used')
    refused(await call(pkce ? PKCE(row) : AC(row)), INVALID, name + ': the right request after it')
  }

  // The client credentials come first: a request without them does not use the code
  for (const [name, pkce, change] of [
    ['wrong client secret', false, { client_secret: 'wrong' }],
    ['wrong client secret (PKCE)', true, { client_secret: 'wrong' }],
    ['unknown client', true, { client_id: 'unknown' }]
  ]) {
    const row = grant(pkce)
    executed.length = 0
    refused(await call({ ...(pkce ? PKCE(row) : AC(row)), ...change }), 'Invalid client credentials.', name)
    ok(!executed.some(e => / grants /.test(e.sql)), name + ': no statement for the code')
    eq(row.fetched, 0)
    tokens(await call(pkce ? PKCE(row) : AC(row)), row, name + ': the right request after it')
  }

  // A request without the parameters, or with a code that is not text: no statement for a code
  {
    const row = grant(true)
    executed.length = 0
    for (const change of [{ code: undefined }, { redirect_uri: undefined }, { client_id: undefined }]) {
      const res = await call({ ...PKCE(row), ...change })
      eq(res.statusCode, 400)
      eq(res.value.error, 'invalid_request')
    }
    for (const code of ['', [row.authorization_code], { toString: () => row.authorization_code }, 5]) refused(await call({ ...PKCE(row), code }), INVALID)
    ok(!executed.some(e => / grants /.test(e.sql)))
    eq(row.fetched, 0)
    tokens(await call(PKCE(row)), row)
  }

  // 5. A code after its end time: refused as before, no tokens, also at the same moment and a second time
  for (const [name, pkce, body] of flows) {
    for (const exp of [Date.now() - 1000, Date.now(), null]) {
      const row = grant(pkce, { exp })
      const answers = await Promise.all([call(body(row)), call(body(row)), call(body(row))])
      for (const res of answers) refused(res, 'Authorization code expired.', name)
      refused(await call(body(row)), 'Authorization code expired.', name)
    }

    // The end time passes while the request waits for the read: the moment after the read counts, no tokens
    const row = grant(pkce, { exp: Date.now() + 1000 })
    pool.afterStatement = sql => { if (/^SELECT \* FROM grants/.test(sql)) clock.offset = 2000 }
    const late = await call(body(row))
    pool.afterStatement = null
    clock.offset = 0
    refused(late, 'Authorization code expired.', name + ': ended during the read')
    eq(row.fetched, 0)
  }

  // 6. A database error: answered without its text, and the code is not used: the same request works after it
  for (const [name, pkce, body] of flows) {
    const error = () => Object.assign(new Error('Connection lost: SQLMARK'), { code: 'PROTOCOL_CONNECTION_LOST', sql: 'SQLMARK' })
    for (const [step, fail] of [
      ['the read of the code', () => { pool.failStatement = { test: /^SELECT \* FROM grants/, error: error() } }],
      ['the update of the code', () => { pool.failStatement = { test: /^UPDATE grants/, error: error() } }]
    ]) {
      const row = grant(pkce)
      fail()
      const answers = await Promise.all([call(body(row)), call(body(row))])
      pool.failStatement = null
      for (const res of answers) serverError(res, name + ', ' + step)
      eq(row.fetched, 0, name + ', ' + step + ': the code is not used')
      tokens(await call(body(row)), row, name + ', ' + step + ': the same request after it')
      refused(await call(body(row)), INVALID)
    }

    // A request that does not fit the code + a database error at the update: the error, the code is not used
    const wrong = grant(pkce)
    pool.failStatement = { test: /^UPDATE grants/, error: error() }
    serverError(await call({ ...body(wrong), redirect_uri: 'https://other.example/cb' }))
    pool.failStatement = null
    eq(wrong.fetched, 0)

    // No connection for the read of the code
    const noRead = grant(pkce)
    pool.afterStatement = sql => { if (/^SELECT \* FROM clients/.test(sql)) pool.failConnection = error() }
    serverError(await call(body(noRead)), name + ': no connection for the read of the code')
    pool.afterStatement = null
    pool.failConnection = null
    eq(noRead.fetched, 0)
    tokens(await call(body(noRead)), noRead, name + ': the same request after it')

    // No connection at all (as before: the client lookup gives no client, so the code is not looked at)
    const row = grant(pkce)
    pool.failConnection = error()
    refused(await call(body(row)), 'Invalid client credentials.', name + ': no connection')
    pool.failConnection = null
    eq(row.fetched, 0)
    tokens(await call(body(row)), row, name + ': the same request after it')
  }

  await new Promise(resolve => setTimeout(resolve, 20))
  eq(unhandled.length, 0, 'no unhandled rejection: ' + unhandled.map(e => e?.message).join(' | '))
  eq(pool.released, pool.taken, 'every connection went back to the pool (also after a statement that failed)')
  ok(pool.taken > 5000)

  // The log of all of the above: no code, verifier, client secret or token
  const text = logged.join('\n')
  for (const mark of ['CODEMARK', 'VERIFIERMARK', 'SECRETMARK', challengeOf(VERIFIER)]) ok(!text.includes(mark), mark + ' is in the log')
  ok(!/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./.test(text), 'a token is in the log')
  ok(logged.includes('verifyAuthorizationCode error Connection lost: SQLMARK'), 'the text of a database error is in the log')
}

;(async () => {
  await suite()
  realLog('codeSingleUse:', n, 'checks OK')
})().catch(e => {
  realLog(e)
  process.exit(1)
})
