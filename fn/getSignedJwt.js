const config = require('../config')
const jwt = require('jsonwebtoken')
const {ISSUER, JWT_LIFE_SPAN, PRIVATE_KEY} = config.jwt

module.exports = function getSignedJWt (jwtData) {
  const token = jwt.sign(jwtData, PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: JWT_LIFE_SPAN,
    issuer: ISSUER,
  })

  return {
    access_token: token,
    token_type: 'bearer',
    expires_in: JWT_LIFE_SPAN / 1000,
  }
}
