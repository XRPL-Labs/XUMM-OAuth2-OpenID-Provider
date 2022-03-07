const {datastore} = require('../datastore')
const renderSignInUi = require('./renderSignInUi')
const returnError = require('./returnError')

module.exports = function handleImplicitAuthRequest (req, res) {
  console.log('handleImplicitAuthRequest')

  if (req.query.client_id === undefined || req.query.redirect_uri === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    .filter('redirect-url', 'LIKE', '%' + req.query.redirect_uri + '%')
    .filter('implicit-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid client/redirect URL.'))
      }
    })
    .then(() => {
      renderSignInUi(req, res, {response_type: 'token'})
    })
    .catch(error => {
      if (error.message === 'Invalid client/redirect URL.') {
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else {
        throw error
      }
    })
}
