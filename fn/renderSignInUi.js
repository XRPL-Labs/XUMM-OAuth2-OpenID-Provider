const path = require('path')
const pug = require('pug')

module.exports = function renderSignInUi (req, res, options) {
  const html = pug.renderFile(path.join(__dirname, '..', 'auth.pug'), {
    ...(options || {}),
    client_id: req.query.client_id,
    redirect_url: req.query.redirect_uri,
    code_challenge: req.query.code_challenge,
    state: req.query?.state,
    nonce: req.query?.nonce,
    scope: req.query?.scope,
  })

  res.status(200).send(html)
}
