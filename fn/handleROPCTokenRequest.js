const {datastore} = require('../datastore')
const getSignedJwt = require('./getSignedJwt')
const returnError = require('./returnError')

module.exports = function handleROPCTokenRequest (req, res) {
  console.log('handleROPCTokenRequest')

  if (req.body.username === undefined || req.body.password === undefined || req.body.client_id === undefined || req.body.client_secret === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
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
      const token = getSignedJwt({})

      res.status(200).json(({
        ...token,
      }))
    })
    .catch(error => {
      if (error.message === 'Invalid client credentials.' || error.message === 'Invalid user credentials.') {
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else {
        throw error;
      }
    })
}
