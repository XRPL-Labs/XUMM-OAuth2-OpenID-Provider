const {datastore} = require('../datastore')
const renderSignInUi = require('./renderSignInUi')
const returnError = require('./returnError')
const redirectUriCheck = require('./redirectUriCheck')

// RFC 7636 4.2: a code challenge has 43 to 128 characters of A-Z a-z 0-9 - . _ ~
const CODE_CHALLENGE = /^[A-Za-z0-9._~-]{43,128}$/
// The name of the method: one short word. The token step checks every challenge as S256, whatever the name, so
// other spellings than `S256` are accepted here as they were.
const CODE_CHALLENGE_METHOD = /^[A-Za-z0-9_-]{1,32}$/

module.exports = function handleACPKCEAuthRequest (req, res) {
  // Every value is one string (a parameter that is given twice is a list)
  if (typeof req.query.client_id !== 'string' || typeof req.query.redirect_uri !== 'string' || req.query.code_challenge === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  // The PKCE values are checked before the sign-in starts. A challenge of another form can never match a code
  // verifier at the token step.
  if (typeof req.query.code_challenge !== 'string' || !CODE_CHALLENGE.test(req.query.code_challenge) || typeof req.query.code_challenge_method !== 'string' || !CODE_CHALLENGE_METHOD.test(req.query.code_challenge_method)) {
    return returnError(req, res, 'invalid_request', 'Invalid code challenge or code challenge method.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    // .filter('redirect-url', 'LIKE', '%' + req.query.redirect_uri + '%')
    .filter('acpkce-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (!redirectUriCheck(result, req.query.redirect_uri)) {
        return Promise.reject(new Error('Invalid client/redirect URL.'))
      }
    })
    .then(() => {
      // Returned: an error of the sign-in start comes to the catch below
      return renderSignInUi(req, res, {response_type: 'code'})
    })
    .catch(error => {
      if (error?.message === 'Invalid client/redirect URL.') {
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else {
        // Any other error (datastore, page, ...): logged, and answered without its text
        console.log('handleACPKCEAuthRequest error', error?.message)
        if (!res.headersSent) returnError(req, res, 'server_error', 'Unexpected error', 500, {})
      }
    })
}
