const crypto = require('crypto')
const sanitizeRedirectUri = require('./sanitizeRedirectUri')
const {datastore} = require('../datastore')

// An authorization code is used once: the first token request that has the code uses it, with or without a token
// as the result. The steps, in this order:
//   1. (the token handler, before this function) the client credentials: a request without them does not get here.
//   2. Read the code. Nothing is changed. A database error ends the request here: the code stays as it was.
//   3. Compare the request with what was read (client, redirect URL, end time, code verifier). In memory only: this
//      step can not fail on something outside the request.
//   4. Take the code, in ONE conditional UPDATE (takeAuthorizationCode). A statement that fails changes nothing:
//      a database error ends the request, the code stays as it was.
//   5. The answer. Step 3 found a difference: its text (the code is used: one attempt per code). No row changed in
//      step 4: another request used the code first, the answer is the one of an unknown code. Else: the entry.
// After step 4 nothing waits on something outside the request, so an error of the database does not use up a code.

const grantQuery = authorizationCode => datastore.createQuery('grant').filter('authorization_code', '=', authorizationCode)

// Takes the code in one conditional UPDATE: it changes the row only while the code is not used (`fetched` 0) and not
// ended, so of all requests that have the same code at the same moment, one changes the row. True: this request
// took the code.
const takeAuthorizationCode = async function takeAuthorizationCode (authorizationCode) {
  const result = await grantQuery(authorizationCode)
    .filter('fetched', '=', 0)
    .filter('exp', '>', Date.now())
    .update({ fetched: 1 })

  return result?.[0]?.affectedRows === 1
}

const challengeOf = codeVerifier => crypto
  .createHash('sha256')
  .update(Buffer.from(codeVerifier))
  .digest()
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '')

// Why the request does not fit the code: the text for the client. It fits: undefined. (The order and the texts are
// as before.)
const refusalReason = function refusalReason (entry, clientId, redirectUrl, codeVerifier) {
  if (entry.client_id !== clientId) {
    return 'Client ID does not match the record.'
  }

  if (typeof entry.redirect_url !== 'string' || typeof redirectUrl !== 'string' || sanitizeRedirectUri(entry.redirect_url) !== sanitizeRedirectUri(redirectUrl)) {
    return 'Redirect URL does not match the record.'
  }

  if (!(entry.exp > Date.now())) {
    return 'Authorization code expired.'
  }

  // A request without a code verifier is the flow with a client secret: the handler checked the secret
  if (codeVerifier !== undefined && entry.code_challenge !== undefined) {
    if (typeof codeVerifier !== 'string' || challengeOf(codeVerifier) !== entry.code_challenge) {
      return 'Code verifier does not match code challenge.'
    }
  }
}

module.exports = async function verifyAuthorizationCode (authorizationCode, clientId, redirectUrl, codeVerifier = undefined) {
  console.log('verifyAuthorizationCode')

  try {
    if (typeof authorizationCode !== 'string' || authorizationCode === '') {
      throw new Error('Invalid authorization code.')
    }

    const entry = (await grantQuery(authorizationCode).filter('fetched', '=', 0).get())[0]

    if (entry === undefined) {
      throw new Error('Invalid authorization code.')
    }

    const reason = refusalReason(entry, clientId, redirectUrl, codeVerifier)
    const taken = await takeAuthorizationCode(authorizationCode)

    if (reason !== undefined) {
      throw new Error(reason)
    }

    if (!taken) {
      // The code was there at the read, and was used (or ended) before the UPDATE of this request
      console.log('verifyAuthorizationCode: the code was used by another request at the same moment', entry.client_id, entry.sub)
      throw new Error('Invalid authorization code.')
    }

    return entry
  } catch (error) {
    console.log('verifyAuthorizationCode error', error?.message)
    throw error
  }
}
