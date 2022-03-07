const getSignedJwt = require('./getSignedJwt')
const datastore = require('../datastore')

module.exports = function handleCCTokenRequest (req, res) {
  console.log('handleCCTokenRequest')

  if (req.body.client_id === undefined || req.body.client_secret === undefined) {
    return res.status(400).json(({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
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
        return res.status(400).json(({
          error: 'access_denied',
          error_description: 'Invalid client credentials.'
        }))
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
