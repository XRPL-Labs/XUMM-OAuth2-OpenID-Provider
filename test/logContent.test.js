// Run: node test/logContent.test.js
//
// What a log line has: the step, the ids of the client and the account, the text of an error. Not a code, a code
// verifier, a token or the other claims of a token.
// The real datastore.js (its statements for the token step), fn/verifyAuthorizationCode.js and fn/jwtAuth.js, with a
// fake config and a database pool that answers from a list. No config file, no database, no network.
const assert = require('assert')
const crypto = require('crypto')
const Module = require('module')
const util = require('util')
const jwt = require('jsonwebtoken')

const CLIENT = '11111111-2222-4333-8444-555555555555'
const ACCOUNT = 'rTestAccount1111111111111111111111'
const REDIRECT = 'https://app.example/cb'
const CODE = 'CODEMARK-' + crypto.randomBytes(16).toString('hex')
const VERIFIER = 'VERIFIERMARK-' + crypto.randomBytes(32).toString('hex')
const CHALLENGE = crypto.createHash('sha256').update(VERIFIER).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

const keys = () => crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' }
})
const fakeConfig = {
  port: 0,
  secret: 'test-secret',
  db: { uri: 'mysql://none' },
  jwt: { ISSUER: 'https://oauth2.test', JWT_LIFE_SPAN: 7200, CODE_LIFE_SPAN: 600, PRIVATE_KEY: keys().privateKey },
  openid: { discovery: { issuer: 'https://oauth2.test' }, certs: [] }
}

// ---- Fake database pool: the table `grants` is a list, a statement can be made to fail
let grants = []
let failStatement = null
const executed = []
const connection = {
  execute: async (text, params) => {
    const sql = text.replace(/\s+/g, ' ').trim()
    executed.push({ sql, params })
    if (failStatement) throw failStatement
    if (sql === 'SELECT * FROM grants WHERE `authorization_code` = ? AND `fetched` = ?') return [grants.filter(g => g.authorization_code === params[0] && g.fetched === params[1]).map(g => ({ ...g })), []]
    if (sql === 'UPDATE grants SET `fetched` = ? WHERE `authorization_code` = ? AND `fetched` = ? AND `exp` > ?') {
      const rows = grants.filter(g => g.authorization_code === params[1] && g.fetched === params[2] && g.exp > params[3])
      rows.forEach(g => { g.fetched = params[0] })
      return [{ affectedRows: rows.length }, undefined]
    }
    throw new Error('fake pool: statement ' + sql)
  },
  release () {}
}

const load = Module._load
Module._load = function (request) {
  if (/^\.\.?\/config$/.test(request)) return fakeConfig
  if (request === 'mysql2/promise') return { createPool: () => ({ getConnection: async () => connection }) }
  return load.apply(this, arguments)
}

// ---- The log: every line as text, objects in full depth
const realLog = console.log
const logged = []
console.log = (...args) => { logged.push(args.map(a => typeof a === 'string' ? a : util.inspect(a, { depth: null, breakLength: Infinity })).join(' ')) }
const text = () => logged.join('\n')
const clear = () => { logged.length = 0; executed.length = 0 }

const verifyAuthorizationCode = require('../fn/verifyAuthorizationCode')
const jwtAuth = require('../fn/jwtAuth')

let n = 0
const ok = (value, message) => { assert.ok(value, message); n++ }
const eq = (a, b, message) => { assert.strictEqual(a, b, message); n++ }
const turn = () => new Promise(resolve => setImmediate(resolve))
const settle = async () => { for (let i = 0; i < 5; i++) await turn() }

// Not in any log line of this file
const marks = ['CODEMARK', 'VERIFIERMARK', CHALLENGE, 'USERTOKENMARK', 'PAYLOADMARK', 'STATEMARK', 'NONCEMARK', 'ENDPOINTMARK', 'SQLMARK']
const clean = () => {
  for (const mark of marks) ok(!text().includes(mark), mark + ' is in the log:\n' + text())
  ok(!/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./.test(text()), 'a token is in the log')
}

const grant = (values = {}) => ({ authorization_code: CODE, client_id: CLIENT, redirect_url: REDIRECT, exp: Date.now() + 600 * 1000, code_challenge: CHALLENGE, sub: ACCOUNT, fetched: 0, ...values })

const suite = async () => {
  // 1. The token step with a good code and verifier: the entry, the code is used. The statements have the code as
  // a value, the log has the step only
  {
    clear()
    grants = [grant()]
    const entry = await verifyAuthorizationCode(CODE, CLIENT, REDIRECT, VERIFIER)
    await settle()
    eq(entry.sub, ACCOUNT)
    eq(entry.client_id, CLIENT)
    eq(grants[0].fetched, 1, 'the code is used')
    eq(executed.length, 2, 'one read, one update')
    for (const e of executed) {
      ok(!e.sql.includes(CODE), 'the code is not in the text of a statement')
      ok(e.params.includes(CODE), 'the code is a value of the statement')
    }
    assert.deepStrictEqual(logged, ['verifyAuthorizationCode']); n++
    clean()
  }

  // 2. Two requests with the code at the same moment: one gets the entry, the log line of the other has the ids of
  // the client and the account
  {
    clear()
    grants = [grant()]
    const results = await Promise.allSettled([verifyAuthorizationCode(CODE, CLIENT, REDIRECT, VERIFIER), verifyAuthorizationCode(CODE, CLIENT, REDIRECT, VERIFIER)])
    await settle()
    eq(results.filter(r => r.status === 'fulfilled').length, 1)
    eq(results.find(r => r.status === 'rejected').reason.message, 'Invalid authorization code.')
    ok(logged.includes(`verifyAuthorizationCode: the code was used by another request at the same moment ${CLIENT} ${ACCOUNT}`), text())
    ok(logged.includes('verifyAuthorizationCode error Invalid authorization code.'), text())
    clean()
  }

  // 3. Refused (with the same error text for the client as before): the log has the reason
  for (const [args, reason] of [
    [['CODEMARK-unknown', CLIENT, REDIRECT, VERIFIER], 'Invalid authorization code.'],
    [[CODE, 'other-client', REDIRECT, VERIFIER], 'Client ID does not match the record.'],
    [[CODE, CLIENT, 'https://other.example/cb', VERIFIER], 'Redirect URL does not match the record.'],
    [[CODE, CLIENT, REDIRECT, 'VERIFIERMARK-other'], 'Code verifier does not match code challenge.'],
  ]) {
    clear()
    grants = [grant()]
    await assert.rejects(verifyAuthorizationCode(...args), e => e.message === reason, reason); n++
    await settle()
    // A request that has the code and does not fit it uses the code: one attempt per code
    eq(grants[0].fetched, args[0] === CODE ? 1 : 0, reason)
    assert.deepStrictEqual(logged, ['verifyAuthorizationCode', 'verifyAuthorizationCode error ' + reason]); n++
    clean()
  }
  {
    clear()
    grants = [grant({ exp: Date.now() - 1000 })]
    await assert.rejects(verifyAuthorizationCode(CODE, CLIENT, REDIRECT, VERIFIER), /^Error: Authorization code expired\.$/); n++
    await settle()
    ok(logged.includes('verifyAuthorizationCode error Authorization code expired.'), text())
    clean()
  }

  // 4. A database error at the token step: the message is logged, not the other fields of the error. The code is
  // not used.
  {
    clear()
    grants = [grant()]
    failStatement = Object.assign(new Error('Connection lost: The server closed the connection.'), { code: 'PROTOCOL_CONNECTION_LOST', sql: 'SELECT SQLMARK ' + CODE })
    await assert.rejects(verifyAuthorizationCode(CODE, CLIENT, REDIRECT, VERIFIER), /Connection lost/); n++
    failStatement = null
    await settle()
    eq(grants[0].fetched, 0)
    ok(logged.includes('verifyAuthorizationCode error Connection lost: The server closed the connection.'), text())
    clean()
  }

  // 5. The bearer token of /userinfo: the claims are on the request as before, the log line has client and account
  const claims = {
    client_id: CLIENT,
    sub: ACCOUNT,
    scope: 'openid',
    state: 'STATEMARK',
    nonce: 'NONCEMARK',
    email: CLIENT + '+' + ACCOUNT + '@oauth2.test',
    app_uuidv4: CLIENT,
    app_name: 'Test app',
    payload_uuidv4: 'PAYLOADMARK-0000-4000-8000-000000000001',
    usertoken_uuidv4: 'USERTOKENMARK-0000-4000-8000-000000000001',
    network_type: 'MAINNET',
    network_endpoint: 'wss://ENDPOINTMARK.test',
    network_id: 0
  }
  const sign = (values, key = fakeConfig.jwt.PRIVATE_KEY, options = {}) => jwt.sign(values, key, { algorithm: 'RS256', issuer: fakeConfig.jwt.ISSUER, expiresIn: 60, ...options })
  const request = async authorization => {
    const req = { headers: authorization === undefined ? {} : { authorization }, server2server: true }
    const res = { statusCode: 200 }
    let next = 0
    res.status = code => { res.statusCode = code; return res }
    res.json = value => { res.value = value; return res }
    jwtAuth(req, res, () => { next++ })
    await settle()
    return { req, res, next }
  }
  {
    clear()
    for (const header of ['Bearer ' + sign(claims), 'bearer ' + sign(claims), sign(claims)]) {
      const { req, res, next } = await request(header)
      eq(next, 1, 'the request goes on')
      eq(res.value, undefined, 'no answer from this step')
      const { iat, exp, iss, ...rest } = req.user
      assert.deepStrictEqual(rest, claims); n++
      eq(iss, fakeConfig.jwt.ISSUER)
    }
    eq(logged.length, 3, text())
    for (const line of logged) eq(line, `jwtAuth { err: false, client_id: '${CLIENT}', sub: '${ACCOUNT}' }`)
    clean()
  }

  // 6. A token that is refused (as before: 403 with the reason, 401 without a token): the log has the reason
  for (const [header, reason] of [
    ['Bearer ' + sign(claims, keys().privateKey), 'invalid signature'],
    ['Bearer ' + sign(claims, fakeConfig.jwt.PRIVATE_KEY, { expiresIn: -10 }), 'jwt expired'],
    ['Bearer ' + sign(claims, fakeConfig.jwt.PRIVATE_KEY, { issuer: 'https://other.test' }), 'jwt issuer invalid. expected: https://oauth2.test'],
    ['Bearer ' + jwt.sign(claims, 'a-shared-secret-of-some-length', { algorithm: 'HS256', issuer: fakeConfig.jwt.ISSUER }), 'invalid algorithm'],
    ['Bearer not-a-token', 'jwt malformed'],
  ]) {
    clear()
    const { req, res, next } = await request(header)
    eq(next, 0, reason)
    eq(req.user, undefined, reason)
    eq(res.statusCode, 403, reason)
    assert.deepStrictEqual(res.value, { error: 'jwt_auth_error', error_description: reason }); n++
    eq(logged.length, 1, text())
    eq(logged[0], `jwtAuth { err: '${reason}', client_id: undefined, sub: undefined }`)
    clean()
  }
  {
    clear()
    const { res, next } = await request(undefined)
    eq(next, 0)
    eq(res.statusCode, 401)
    assert.deepStrictEqual(res.value, { error: 'invalid_jwt', error_description: 'No JWT token (auth) specified.' }); n++
    eq(logged.length, 0, text())
  }

  // 7. index.js uses this step for /userinfo
  const index = require('fs').readFileSync(require('path').join(__dirname, '..', 'index.js'), 'utf8')
  ok(index.includes("const jwtAuth = require('./fn/jwtAuth')"))
  ok(index.includes("app.use('(/oauth)?/userinfo', jwtAuth, async (req, res) => {"))
}

;(async () => {
  await suite()
  realLog('logContent:', n, 'checks OK')
})().catch(e => {
  realLog(e)
  process.exit(1)
})
