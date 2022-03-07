const {datastore} = require('../datastore')
const renderSignInUi = require('./renderSignInUi')

module.exports = function handleACPKCEAuthRequest (req, res) {
  if (req.query.client_id === undefined || req.query.redirect_uri === undefined || req.query.code_challenge === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    .filter('redirect-url', 'LIKE', '%' + req.query.redirect_uri + '%')
    .filter('acpkce-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid client/redirect URL.'))
      }
    })
    .then(() => {
      renderSignInUi(req, res, {response_type: 'code'})
    })
    .catch(error => {
      if (error.message === 'Invalid client/redirect URL.') {
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else {
        throw error
      }
    })
}
