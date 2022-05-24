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

Nice test-tool:
    - https://oauth.tools/collection/1599045265746-zCR

## XUMM Database

Clients:
```
CREATE VIEW
  clients
AS 
SELECT
    `application_id` as id,
    `application_uuidv4_txt` as `client-id`,
    `application_redirect_uris` as `redirect-url`,
    `application_secret_txt` as `client-secret`,
    0 as `implicit-enabled`,
    1 as `ac-enabled`,
    1 as `acpkce-enabled` ,
    0 as `ropc-enabled`,
    0 as `cc-enabled`,
    'XUMMAPI' as `signin-method`
FROM
    `xrpllabs_sp`.`applications`
WHERE
    `application_disabled` = 0
```
