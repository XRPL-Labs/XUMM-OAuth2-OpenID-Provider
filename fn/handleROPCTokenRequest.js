const config = require('../config')

const datastore = require('../datastore')
const fs = require('fs')
const jwt = require('jsonwebtoken')

const {ISSUER, JWT_LIFE_SPAN, PRIVATE_KEY} = config.jwt

module.exports = function handleROPCTokenRequest (req, res) {
  console.log('handleROPCTokenRequest')

  if (req.body.username === undefined || req.body.password === undefined || req.body.client_id === undefined || req.body.client_secret === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('ropc-enabled', '=', true)

  const userQuery = datastore
    .createQuery('user')
    .filter('username', '=', req.body.username)
    .filter('password', '=', req.body.password)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid client credentials.'))
      }
    })
    .then(() => datastore.runQuery(userQuery))
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid user credentials.'))
      }
    })
    .then(() => {
      const token = jwt.sign({}, PRIVATE_KEY, {
        algorithm: 'RS256',
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER
      })
      res.status(200).json(({
        access_token: token,
        token_type: 'bearer',
        expires_in: JWT_LIFE_SPAN
      }))
    })
    .catch(error => {
      if (error.message === 'Invalid client credentials.' || error.message === 'Invalid user credentials.') {
        res.status(400).json(({
          error: 'access_denied',
          error_description: error.message
        }))
      } else {
        throw error;
      }
    })
}
