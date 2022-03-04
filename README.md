# XUMM OAuth2 server

Sign In gateway providing OAuth2 provider services based on XUMM platform Sign In.

### Setup

1. Generate `/private.pem`
2. Derive `/public.pem`
3. Copy `config.sample.js` to `config.js` and enter details.

### Testing Tools

- https://oauthdebugger.com/
- https://oidcdebugger.com/

### Testing notes

http://localhost:9000/auth?client_id=sample-implicit-client&redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug&scope=sample&response_type=code&response_mode=query&nonce=pdrzkco1r5s

E.g.

```
TOKEN=xxx

curl -d "grant_type=authorization_code&client_id=sample-ac-client&client_secret=sample-client-secret&authorization_code=$TOKEN&redirect_uri=https://oauthdebugger.com/debug" -X POST "http://localhost:9000/token"
```

```
TOKEN=xxx

curl -H "authorization: bearer $TOKEN" localhost:9000/me
```
