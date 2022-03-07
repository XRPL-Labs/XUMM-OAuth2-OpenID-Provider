const getSignedJwt = require('./getSignedJwt')
const {datastore} = require('../datastore')
const returnError = require('./returnError')

module.exports = function handleCCTokenRequest (req, res) {
  console.log('handleCCTokenRequest')

  if (req.body.client_id === undefined || req.body.client_secret === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('cc-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return returnError(req, res, 'access_denied', 'Invalid client credentials.', 400, {})
      } else {
        const token = getSignedJwt({
          client_id: req.body.client_id,
          state: req.body?.state || undefined,
          scope: req.body?.scope || undefined,  
          nonce: req.body?.nonce || undefined,
          aud: req.body.client_id,
          sub: null, // TODO
        })

        res.status(200).json(({
          ...token,
          refresh_token: '',
        }))
      }
    })
}
