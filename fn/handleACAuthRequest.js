const datastore = require('../datastore')
const renderSignInUi = require('./renderSignInUi')

module.exports = function handleACAuthRequest (req, res) {
  console.log('handleACAuthRequest')
  if (req.query.client_id === undefined || req.query.redirect_uri === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    .filter('redirect-url', 'LIKE', '%' + req.query.redirect_uri + '%')
    .filter('ac-enabled', '=', true);

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
        res.status(400).json(({
          error: 'access_denied',
          error_description: error.message
        }));
      } else {
        throw error
      }
    })
}
