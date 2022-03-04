const config = require('../config')

const verifyAuthorizationCode = require('./verifyAuthorizationCode')

const datastore = require('../datastore')
const jwt = require('jsonwebtoken')

const {ISSUER, JWT_LIFE_SPAN, PRIVATE_KEY} = config.jwt

module.exports = function handleACTokenRequest (req, res) {
  console.log('handleACTokenRequest')

  if (req.body.client_id === undefined || req.body.client_secret === undefined || (req.body.authorization_code === undefined && req.body.code === undefined) || req.body.redirect_uri === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('ac-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(clientQueryResult => {
      if (clientQueryResult[0].length === 0) {
        return Promise.reject(new Error('Invalid client credentials.'))
      }
    })
    .then(() => {
      return verifyAuthorizationCode(req.body?.authorization_code || req.body?.code, req.body.client_id, req.body.redirect_uri)
    })
    .then(entry => {
      console.log('handleACTokenRequest', {entry})
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

      const jwtResponseData = {
        access_token: token,
        id_token: (entry?.scope || '').match(/openid/i) ? token : undefined,
        refresh_token: '',
        token_type: 'bearer',
        expires_in: JWT_LIFE_SPAN,
        scope: entry?.scope || undefined,
      }

      // console.log(jwtResponseData)
      res.status(200).json(jwtResponseData)
    })
    .catch(error => {
      if (error.message === 'Invalid client credentials.' || error.message === 'Invalid authorization code.' || error.message === 'Client ID does not match the record.' || error.message === 'Redirect URL does not match the record.' || error.message === 'Authorization code expired.') {
        res.status(400).json(({
          error: 'access_denied',
          error_description: error.message
        }))
      } else {
        throw error
      }
    })
}
