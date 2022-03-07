const verifyAuthorizationCode = require('./verifyAuthorizationCode')
const getSignedJwt = require('./getSignedJwt')
const {datastore} = require('../datastore')

module.exports = function handleACPKCETokenRequest (req, res) {
  console.log('handleACPKCETokenRequest', req.body)

  if (req.body.client_id === undefined || (req.body.authorization_code === undefined && req.body.code === undefined) || req.body.redirect_uri === undefined || req.body.code_verifier === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('acpkce-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(clientQueryResult => {
      if (clientQueryResult[0].length === 0) {
        return Promise.reject(new Error('Invalid client credentials.'))
      }
    })
    .then(() => {
      return verifyAuthorizationCode(req.body?.authorization_code || req.body?.code, req.body.client_id, req.body.redirect_uri, req.body.code_verifier)
    })
    .then(entry => {
      console.log('handleACPKCETokenRequest', {entry})
      const token = getSignedJwt({
        client_id: entry?.client_id,
        state: entry?.state || undefined,
        scope: entry?.scope || undefined,
        aud: entry?.client_id,
        sub: entry?.sub,
        nonce: entry?.nonce || undefined,
        // TODO: custom user props matching config claims (user profile)
      })

      res.status(200).json(({
        ...token,
        id_token: (entry?.scope || '').match(/openid/i) ? token.access_token : undefined,
        refresh_token: '',
        scope: entry?.scope || undefined,
      }))
    })
    .catch(error => {
      if (error.message === 'Invalid client credentials.' || error.message === 'Invalid authorization code.' || error.message === 'Client ID does not match the record.' || error.message === 'Redirect URL does not match the record.' || error.message === 'Authorization code expired.' || error.message === 'Code verifier does not match code challenge.') {
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else if (error.msg === 'Code challenge does not exist.') {
        returnError(req, res, 'invalid_request', error.message, 400, {})
      } else {
        throw error
      }
    })
}
