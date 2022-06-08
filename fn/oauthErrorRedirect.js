const appendQuery = require('append-query')

// User denied:
//  - access_denied
// Other errors:
//  - invalid_request
//  - unauthorized_client
//  - unsupported_response_type
//  - invalid_scope
//  - server_error
//  - temporarily_unavailable

module.exports = function oauthErrorRedirect (res, return_url, error_code, error_description) {
  return res.redirect(appendQuery(return_url, {error: error_code, error_description}))
}
