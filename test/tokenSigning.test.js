// Run: node test/tokenSigning.test.js
// The token library signs and verifies on this Node version (its constant time comparison comes from vendor/).
const assert = require('assert')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const bufferEq = require('buffer-equal-constant-time')

let checks = 0
const ok = (value, text) => { assert.ok(value, text); checks++ }
const eq = (a, b, text) => { assert.strictEqual(a, b, text); checks++ }

// The comparison itself
eq(bufferEq(Buffer.from('abc'), Buffer.from('abc')), true, 'same bytes')
eq(bufferEq(Buffer.from('abc'), Buffer.from('abd')), false, 'other bytes')
eq(bufferEq(Buffer.from('abc'), Buffer.from('abcd')), false, 'other length')
eq(bufferEq(Buffer.alloc(0), Buffer.alloc(0)), true, 'two empty buffers')
for (const other of ['abc', null, undefined, 5, {}, [97, 98, 99], new Uint8Array([97, 98, 99])]) {
  eq(bufferEq(Buffer.from('abc'), other), false, 'not a buffer: ' + typeof other)
  eq(bufferEq(other, Buffer.from('abc')), false, 'not a buffer first: ' + typeof other)
}
eq(typeof bufferEq.install, 'function'); eq(typeof bufferEq.restore, 'function')

// HMAC token (this comparison is used for it)
const secret = 'a-test-secret-of-some-length'
const token = jwt.sign({ sub: 'rTest', client_id: 'c' }, secret, { algorithm: 'HS256', expiresIn: 60 })
eq(jwt.verify(token, secret, { algorithms: ['HS256'] }).sub, 'rTest', 'HS256 round trip')
assert.throws(() => jwt.verify(token, secret + 'x', { algorithms: ['HS256'] }), /invalid signature/); checks++
const parts = token.split('.')
const forged = [parts[0], Buffer.from(JSON.stringify({ sub: 'rOther' })).toString('base64url'), parts[2]].join('.')
assert.throws(() => jwt.verify(forged, secret, { algorithms: ['HS256'] }), /invalid signature/); checks++

// RSA token (as the service signs its id tokens)
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } })
const rs = jwt.sign({ sub: 'rTest' }, privateKey, { algorithm: 'RS256', expiresIn: 60 })
eq(jwt.verify(rs, publicKey, { algorithms: ['RS256'] }).sub, 'rTest', 'RS256 round trip')
const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } })
assert.throws(() => jwt.verify(rs, other.publicKey, { algorithms: ['RS256'] }), /invalid signature/); checks++
assert.throws(() => jwt.verify(rs, publicKey, { algorithms: ['HS256'] })); checks++
ok(true)

console.log('tokenSigning: ' + checks + ' checks OK')
