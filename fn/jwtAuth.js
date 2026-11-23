const jwt = require('jsonwebtoken')
const config = require('../config')
const returnError = require('./returnError')
const {ISSUER, PRIVATE_KEY} = config.jwt

// The bearer token of a request (/userinfo): verified, its claims are `req.user`.
// The log line has the result, the client and the account. The other claims of the token are not logged.
module.exports = function jwtAuth (req, res, next) {
  const authHeader = req.headers?.authorization
  const token = authHeader && authHeader.trim().split(' ').reverse()[0].trim()

  if (token == null) return returnError(req, res, 'invalid_jwt', 'No JWT token (auth) specified.', 401, {})

  jwt.verify(token, PRIVATE_KEY, {
    algorithms: ['RS256'],
    issuer: ISSUER,
  }, (err, user) => {
    console.log('jwtAuth', {err: err ? err.message : false, client_id: user?.client_id, sub: user?.sub})

    if (err) return returnError(req, res, 'jwt_auth_error', err?.message || 'Unspecified', 403, err)

    req.user = user

    next()
  })
}
