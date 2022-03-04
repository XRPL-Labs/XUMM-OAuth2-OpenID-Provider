const config = require('../config')

const verifyAuthorizationCode = require('./verifyAuthorizationCode')

const datastore = require('../datastore')
const jwt = require('jsonwebtoken')

const {ISSUER, JWT_LIFE_SPAN, PRIVATE_KEY} = config.jwt

module.exports = function handleACPKCETokenRequest (req, res) {
  console.log('handleACPKCETokenRequest', req.body)

  if (req.body.client_id === undefined || (req.body.authorization_code === undefined && req.body.code === undefined) || req.body.redirect_uri === undefined || req.body.code_verifier === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
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
      const token = jwt.sign({
        client_id: entry?.client_id,
        state: entry?.state || undefined,
        scope: entry?.scope || undefined,
        aud: entry?.client_id,
        sub: entry?.sub,
        nonce: entry?.nonce || undefined,
        // TODO: custom user props matching config claims (user profile)
      }, PRIVATE_KEY, {
        algorithm: 'RS256',
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER,
      })
      res.status(200).json(({
        access_token: token,
        id_token: (entry?.scope || '').match(/openid/i) ? token : undefined,
        refresh_token: '',
        token_type: 'bearer',
        expires_in: JWT_LIFE_SPAN,
        scope: entry?.scope || undefined,
      }))
    })
    .catch(error => {
      if (error.message === 'Invalid client credentials.' || error.message === 'Invalid authorization code.' || error.message === 'Client ID does not match the record.' || error.message === 'Redirect URL does not match the record.' || error.message === 'Authorization code expired.' || error.message === 'Code verifier does not match code challenge.') {
        res.status(400).json(({
          error: 'access_denied',
          error_description: error.message
        }))
      } else if (error.msg === 'Code challenge does not exist.') {
        res.status(400).json(({
          error: 'invalid_request',
          error_description: error.message
        }))
      } else {
        throw error
      }
    })
}
