const {datastore} = require('../datastore')
const renderSignInUi = require('./renderSignInUi')
const returnError = require('./returnError')
const redirectUriCheck = require('./redirectUriCheck')

module.exports = function handleACAuthRequest (req, res) {
  console.log('handleACAuthRequest')
  // Every value is one string (a parameter that is given twice is a list)
  if (typeof req.query.client_id !== 'string' || typeof req.query.redirect_uri !== 'string') {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    // .filter('redirect-url', 'LIKE', '%' + req.query.redirect_uri + '%')
    .filter('ac-enabled', '=', true);

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (!redirectUriCheck(result, req.query.redirect_uri)) {
        return Promise.reject(new Error('Invalid client/redirect URL.'))
      }
    })
    .then(() => {
      // Returned: an error of the sign-in start comes to the catch below
      return renderSignInUi(req, res, {response_type: 'code'})
    })
    .catch(error => {
      if (error?.message === 'Invalid client/redirect URL.') {
        
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else {
        // Any other error (datastore, page, ...): logged, and answered without its text
        console.log('handleACAuthRequest error', error?.message)
        if (!res.headersSent) returnError(req, res, 'server_error', 'Unexpected error', 500, {})
      }
    })
}
