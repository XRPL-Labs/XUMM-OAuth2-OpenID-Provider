const config = require('../config')
const getSignedJwt = require('./getSignedJwt')
const appendQuery = require('append-query')
const {datastore} = require('../datastore')
const returnError = require('./returnError')
const redirectUriCheck = require('./redirectUriCheck')

module.exports = function handleImplictSigninRequest (req, res) {
  console.log('handleImplictSigninRequest')

  if (req.body.username === undefined || req.body.password === undefined || req.body.client_id === undefined || req.body.redirect_uri === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const userQuery = datastore
    .createQuery('user')
    .filter('username', '=', req.body.username)
    .filter('password', '=', req.body.password)

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    // .filter('redirect-url', 'LIKE', '%' + req.body.redirect_uri + '%')
    .filter('implicit-enabled', '=', true)

  let sub = null // username

  datastore
    .runQuery(userQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid user credentials.'))
      } else {
        sub = result[0][0].username
      }
    })
    .then(() => {
      return datastore.runQuery(clientQuery)
    })
    .then(result => {
      if (!redirectUriCheck(result, req.body.redirect_uri)) {
        return Promise.reject(new Error('Invalid client and/or redirect URL.'))
      }
    })
    .then(() => {
      const token = getSignedJwt({
        client_id: req.body.client_id,
        state: req.body?.state || undefined,
        scope: req.body?.scope || undefined,
        nonce: req.body?.nonce || undefined,
        aud: req.body.client_id,
        sub,
        email: req.body.client_id + '+' + sub + '@' + (config.maildomain || 'oauth2.local'),

        app_uuidv4: req.body.client_id,
        app_name: req.body?.xumm_app_name || undefined,

        payload_uuidv4: req.body?.xumm_payload || undefined,

        usertoken_uuidv4: req.body?.xumm_app_usertoken || undefined,

        network_type: req.body?.xumm_network_type || undefined,
        network_endpoint: req.body?.xumm_network_endpoint || undefined,
      })

      res.redirect(appendQuery(req.body.redirect_uri, {
        ...token,
        refresh_token: '',
        state: req.body?.state || undefined,
        nonce: req.body?.nonce || undefined,
      }))
    })
}
