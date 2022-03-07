const getSignedJwt = require('./getSignedJwt')
const appendQuery = require('append-query')
const {datastore} = require('../datastore')

module.exports = function handleImplictSigninRequest (req, res) {
  console.log('handleImplictSigninRequest')

  if (req.body.username === undefined || req.body.password === undefined || req.body.client_id === undefined || req.body.redirect_uri === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  const userQuery = datastore
    .createQuery('user')
    .filter('username', '=', req.body.username)
    .filter('password', '=', req.body.password)

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('redirect-url', 'LIKE', '%' + req.body.redirect_uri + '%')
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
      if (result[0].length === 0) {
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
        sub
      })

      res.redirect(appendQuery(req.body.redirect_uri, {
        ...token,
        refresh_token: '',
        state: req.body?.state || undefined,
        nonce: req.body?.nonce || undefined,
      }))
    })
}
