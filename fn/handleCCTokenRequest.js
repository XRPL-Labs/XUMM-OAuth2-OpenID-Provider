const config = require('../config')

const datastore = require('../datastore')
const fs = require('fs')
const jwt = require('jsonwebtoken')

const {ISSUER, JWT_LIFE_SPAN, PRIVATE_KEY} = config.jwt

module.exports = function handleCCTokenRequest (req, res) {
  console.log('handleCCTokenRequest')

  if (req.body.client_id === undefined || req.body.client_secret === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('cc-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return res.status(400).json(({
          error: 'access_denied',
          error_description: 'Invalid client credentials.'
        }))
      } else {
        const token = jwt.sign({
          client_id: req.body.client_id,
          state: req.body?.state || undefined,
          scope: req.body?.scope || undefined,  
          nonce: req.body?.nonce || undefined,
          aud: req.body.client_id,
          sub: null, // TODO
        }, PRIVATE_KEY, {
          algorithm: 'RS256',
          expiresIn: JWT_LIFE_SPAN,
          issuer: ISSUER,
        })
        res.status(200).json(({
          access_token: token,
          refresh_token: '',
          token_type: 'bearer',
          expires_in: JWT_LIFE_SPAN
        }))
      }
    })
}
