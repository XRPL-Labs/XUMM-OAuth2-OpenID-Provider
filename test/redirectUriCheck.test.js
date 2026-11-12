// Run: node test/redirectUriCheck.test.js
const assert = require('assert')
const check = require('../fn/redirectUriCheck')
const reg = urls => [[{ 'redirect-url': urls.join('\n') }]]
const allowed = (urls, uri) => !!check(reg(urls), uri)

const yes = [
  [['https://xpmarket.com'], 'https://xpmarket.com'],
  [['https://xpmarket.com'], 'https://xpmarket.com/'],
  [['https://xpmarket.com'], 'https://xpmarket.com/callback?x=1#y'],
  [['https://xpmarket.com/'], 'https://xpmarket.com/callback'],
  [['https://XPMarket.com'], 'https://xpmarket.com/callback'],
  [['https://xpmarket.com'], 'https://XPMARKET.COM/callback'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/cb'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/cb/'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/cb/deeper'],
  [['https://xpmarket.com:8443'], 'https://xpmarket.com:8443/x'],
  [['https://xpmarket.com:443'], 'https://xpmarket.com/x'], // default port
  [['http://localhost:3000'], 'http://localhost:3000/'],
  [['http://localhost:3000'], 'http://localhost:3000/auth/callback'],
  [['http://localhost'], 'http://localhost/x'],
  [['http://127.0.0.1:5173'], 'http://127.0.0.1:5173/'],
  [['https://*.example.com'], 'https://a.example.com/x'],
  [['https://*.example.com'], 'https://a.b.example.com'],
  [['https://a.io', 'https://b.io'], 'https://b.io/x'],
  [['  https://a.io  ', 'https://b.io\r'], 'https://b.io/x'],
  [['myapp://callback'], 'myapp://callback'],
  [['myapp://callback'], 'myapp://callback/done'],
  [['https://xcannes.xyz/*'], 'https://xcannes.xyz/auth/callback'], // `/*`: any path of that origin
  [['https://ripplerocket.fun/xumm-login/*'], 'https://ripplerocket.fun/xumm-login/done'],
  [['http://localhost:5173 (for local testing)'], 'http://localhost:5173/cb'], // a note after the URI
  [['http://localhost:5173, http://localhost:3000'], 'http://localhost:3000/cb'], // several on one line
  [['http://localhost:5173;http://192.168.1.131:3000'], 'http://192.168.1.131:3000/'],
  [['https://pathledger.org <br/> https://dev.pathledger.org'], 'https://dev.pathledger.org/x'],
  [['myapp://'], 'myapp://callback'], // a bare custom scheme: every URI of that scheme
  [['myapp://'], 'myapp://anything/else?x=1'],
  [['allthemarket://', 'https://allthemarket.app/callback'], 'allthemarket://xaman-callback'],
  [['https://app-*.vercel.app'], 'https://app-pr-123-team.vercel.app/cb'], // a wildcard inside a label
  [['https://xrp.*.workers.dev'], 'https://xrp.589.workers.dev'],
  [['https://*.589.workers.dev'], 'https://xrp.589.workers.dev/x'],
  [['https://kwokfi-dev--**.web.app'], 'https://kwokfi-dev--pr12-abc.web.app'],
  [['https://*.example.co.uk'], 'https://shop.example.co.uk'],
  [['file:///C:/Users/dev/app/'], 'file:///C:/Users/dev/app/index.html'],
  [['https://xpmarket.com/call'], 'https://xpmarket.com/callback'], // path prefix, same origin (as before)
  [['http://localhost'], 'http://localhost:3000/x'], // loopback without a port: any port
  [['http://127.0.0.1'], 'http://127.0.0.1:8080/'],
]
const no = [
  [['https://xpmarket.com'], 'https://xpmarket.com.attacker.net/cb'],
  [['https://xpmarket.com'], 'https://xpmarket.com.attacker.net'],
  [['https://xpmarket.com'], 'https://xpmarket.com@attacker.net/cb'],
  [['https://xpmarket.com'], 'https://xpmarket.com:443@attacker.net/cb'],
  [['https://xpmarket.com'], 'https://xpmarket.com%40attacker.net'],
  [['https://xpmarket.com'], 'https://user:pass@xpmarket.com/'],
  [['https://xpmarket.com'], 'https://xpmarket.comm'],
  [['https://xpmarket.com'], 'https://xpmarket.comX.example'],
  [['https://xpmarket.com'], 'http://xpmarket.com/'],
  [['https://xpmarket.com'], 'https://xpmarket.com:8443/'],
  [['https://xpmarket.com'], 'https://evil.com/https://xpmarket.com'],
  [['https://xpmarket.com'], 'https://evil.com\\@xpmarket.com'],
  [['https://xpmarket.com'], 'javascript://xpmarket.com/%0aalert(1)'],
  [['https://xpmarket.com/'], 'https://xpmarket.com.attacker.net/cb'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/cb/../../evil'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/cb/..%2f..%2fevil'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/other'],
  [['https://xpmarket.com/cb'], 'https://xpmarket.com/'],
  [['http://localhost:3000'], 'http://localhost:3000.evil.com/'],
  [['http://localhost'], 'http://localhost.evil.com/'],
  [['http://localhost:3000'], 'http://localhost:3001/'],
  [['http://localhost'], 'http://localhost.evil.com:3000/'],
  [['http://localhost'], 'http://127.0.0.1:3000/'],
  [['https://example.com'], 'https://example.com:3000/'], // any port: loopback only
  [['https://*.example.com'], 'https://example.com/x'],
  [['https://*.example.com'], 'https://evil.com/.example.com'],
  [['https://*.example.com'], 'https://a.example.com.evil.com/x'],
  [['https://*.example.com'], 'https://a.example.com@evil.com/x'],
  [['https://*.example.com'], 'https://evilexample.com/x'],
  [['https://*.example.com'], 'http://a.example.com/x'],
  [['https://*.example.com', 'https://x.io'], 'https://x.io.evil.com'],
  [['https://*.'], 'https://anything.com'],
  [['https://xcannes.xyz/*'], 'https://xcannes.xyz.evil.com/auth'],
  [['https://ripplerocket.fun/xumm-login/*'], 'https://ripplerocket.fun/other'],
  [['https://*/callback'], 'https://evil.com/callback'],
  [['https://*vercel.app'], 'https://evilvercel.app'],
  [['http://localhost:5173 (for https://evil.com testing)'], 'https://evil.com.attacker.net/'],
  [['see: example.com'], 'https://example.com/'], // no scheme: not a URI
  // `https://` registered (was: every site): nothing
  [['https://'], 'https://anything.com'],
  [['https://', 'http://'], 'http://anything.com/x'],
  [['https:'], 'https://anything.com'],
  [['myapp://'], 'https://evil.com'],
  [['myapp://'], 'myapp2://callback'],
  // Wildcards: never in the registrable part
  [['https://*.com'], 'https://evil.com'],
  [['https://*'], 'https://evil.com'],
  [['https://example.*'], 'https://example.evil'],
  [['https://*.co.uk'], 'https://evil.co.uk'],
  [['https://app-*.vercel.app'], 'https://app-x.evil.vercel.app'], // inside a label: one label only
  [['https://app-*.vercel.app'], 'https://app-.vercel.app'],
  [['https://app-*.vercel.app'], 'https://app-x.vercel.app.evil.com'],
  [['https://app-*.vercel.app'], 'https://evil.com/app-x.vercel.app'],
  [['https://xrp.*.workers.dev'], 'https://xrp.workers.dev'],
  [['https://xrp.*.workers.dev'], 'https://xrp.a.workers.dev@evil.com'],
  [['https://*.example.com'], 'https://a.example.com:8443/'],
  [['file:///C:/Users/dev/app/'], 'file:///C:/Users/other/'],
  [['myapp://callback'], 'myapp://callbackx'],
  [['myapp://callback'], 'otherapp://callback'],
  [['https://xpmarket.com'], ''],
  [['https://xpmarket.com'], 'not a url'],
  [[''], 'https://xpmarket.com'],
]
let n = 0
yes.forEach(([urls, uri]) => { assert.strictEqual(allowed(urls, uri), true, `must be ALLOWED: ${JSON.stringify(urls)} <- ${uri}`); n++ })
no.forEach(([urls, uri]) => { assert.strictEqual(allowed(urls, uri), false, `must be REFUSED: ${JSON.stringify(urls)} <- ${uri}`); n++ })
assert.strictEqual(check(undefined, 'https://a.io'), false)
assert.strictEqual(check([[]], 'https://a.io'), false)
assert.strictEqual(check(reg(['https://a.io']), undefined), false)
assert.strictEqual(check(reg(['https://a.io']), ['https://a.io']), false)
const result = reg(['https://a.io'])
assert.strictEqual(check(result, 'https://a.io/x'), result) // returns the db result, as before
console.log('redirectUriCheck:', n + 5, 'checks OK')
