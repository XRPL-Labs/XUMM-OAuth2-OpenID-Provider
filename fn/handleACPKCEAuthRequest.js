const datastore = require('../datastore')
const path = require('path')
const pug = require('pug')

module.exports = function handleACPKCEAuthRequest (req, res) {
  if (req.query.client_id === undefined || req.query.redirect_uri === undefined || req.query.code_challenge === undefined) {
    return res.status(400).send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'Required parameters are missing in the request.'
    }))
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('redirect-url', 'LIKE', '%' + req.body.redirect_uri + '%')
    .filter('acpkce-enabled', '=', true)

  datastore
    .runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid client/redirect URL.'))
      }
    })
    .then(() => {
      const html = pug.renderFile(path.join(__dirname, '..', 'auth.pug'), {
        response_type: 'code',
        client_id: req.query.client_id,
        redirect_url: req.query.redirect_uri,
        code_challenge: req.query.code_challenge,
        state: req.query?.state,
        nonce: req.query?.nonce,
        scope: req.query?.scope,
      });
      res.status(200).send(html)
    })
    .catch(error => {
      if (error.message === 'Invalid client/redirect URL.') {
        res.status(400).send(JSON.stringify({
          error: 'access_denied',
          error_description: error.message
        }));
      } else {
        throw error
      }
    })
}
