const config = require('../config')
const getSignedJwt = require('./getSignedJwt')
const verifyAuthorizationCode = require('./verifyAuthorizationCode')
const {datastore} = require('../datastore')
const returnError = require('./returnError')

module.exports = function handleACTokenRequest (req, res) {
  console.log('handleACTokenRequest')

  if (req.body.client_id === undefined || req.body.client_secret === undefined || (req.body.authorization_code === undefined && req.body.code === undefined) || req.body.redirect_uri === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('ac-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(clientQueryResult => {
      if (clientQueryResult[0].length === 0) {
        return Promise.reject(new Error('Invalid client credentials.'))
      }
    })
    .then(() => {
      return verifyAuthorizationCode(req.body?.authorization_code || req.body?.code, req.body.client_id, req.body.redirect_uri)
    })
    .then(entry => {
      console.log('handleACTokenRequest', {entry})
      const token = getSignedJwt({
        client_id: entry?.client_id,
        // state: entry?.state || undefined,
        scope: entry?.scope || undefined,
        aud: entry?.client_id,
        sub: entry?.sub,
        email: entry?.client_id + '+' + entry?.sub + '@' + (config.maildomain || 'oauth2.local'),
        nonce: entry?.nonce || undefined,

        app_uuidv4: entry.client_id,
        app_name: entry?.xumm_app_name || undefined,

        payload_uuidv4: entry?.xumm_payload || undefined,

        usertoken_uuidv4: entry?.xumm_app_usertoken || undefined,

        network_type: entry?.xumm_network_type || undefined,
        network_endpoint: entry?.xumm_network_endpoint || undefined,
        network_id: entry?.xumm_network_id || undefined,
      })
      
      const jwtResponseData = {
        ...token,
        id_token: (entry?.scope || '').match(/openid/i) ? token.access_token : undefined,
        refresh_token: '',
        scope: entry?.scope || undefined,
      }

      // console.log(jwtResponseData)
      res.status(200).json(jwtResponseData)
    })
    .catch(error => {
      if (error.message === 'Invalid client credentials.' || error.message === 'Invalid authorization code.' || error.message === 'Client ID does not match the record.' || error.message === 'Redirect URL does not match the record.' || error.message === 'Authorization code expired.') {
        returnError(req, res, 'access_denied', error.message, 400, {})
      } else {
        throw error
      }
    })
}
