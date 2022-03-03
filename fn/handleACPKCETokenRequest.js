const config = require('../config')

const verifyAuthorizationCode = require('./verifyAuthorizationCode')

const fs = require('fs')
const jwt = require('jsonwebtoken')

const {ISSUER, JWT_LIFE_SPAN, PRIVATE_KEY} = config.jwt

module.exports = function handleACPKCETokenRequest (req, res) {
  console.log('handleACPKCETokenRequest')

  if (req.body.client_id === undefined || req.body.authorization_code === undefined || req.body.redirect_uri === undefined || req.body.code_verifier === undefined) {
    return res.status(400).send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  verifyAuthorizationCode(req.body.authorization_code, req.body.client_id, req.body.redirect_uri, req.body.code_verifier)
    .then(() => {
      const token = jwt.sign({
        client_id: req.body.client_id,
        state: req.body?.state || undefined,
        scope: req.body?.scope || undefined,
        nonce: req.body?.nonce || undefined,
      }, PRIVATE_KEY, {
        algorithm: 'RS256',
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER,
      })
      res.status(200).send(JSON.stringify({
        access_token: token,
        token_type: 'JWT',
        expires_in: JWT_LIFE_SPAN
      }))
    })
    .catch(error => {
      if (error.message === 'Invalid authorization code.' || error.message === 'Client ID does not match the record.' || error.message === 'Redirect URL does not match the record.' || error.message === 'Authorization code expired.' || error.message === 'Code verifier does not match code challenge.') {
        res.status(400).send(JSON.stringify({
          error: 'access_denied',
          error_description: error.message
        }))
      } else if (error.msg === 'Code challenge does not exist.') {
        res.status(400).send(JSON.stringify({
          error: 'invalid_request',
          error_description: error.message
        }))
      } else {
        throw error
      }
    })
}