const config = require('../config')
const appendQuery = require('append-query')
const {datastore} = require('../datastore')
const returnError = require('./returnError')
const fernet = require('fernet')
const redirectUriCheck = require('./redirectUriCheck')
const renderPkceRedirect = require('./renderPkceRedirect')

const {CODE_LIFE_SPAN} = config.jwt
const fernetToken = new fernet.Token({ secret: new fernet.Secret(config.secret) })

module.exports = function handleACPKCESigninRequest (req, res) {
  console.log('handleACPKCESigninRequest')

  if (req.body.username === undefined || req.body.password === undefined || req.body.client_id === undefined || req.body.redirect_uri === undefined || req.body.code_challenge === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  const userQuery = datastore
    .createQuery('user')
    .filter('username', '=', req.body.username)
    .filter('password', '=', req.body.password)

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    // .filter('redirect-url', 'LIKE', '%' + req.body.redirect_uri + '%')
    .filter('acpkce-enabled', '=', true)

  let sub = null // username

  datastore
    .runQuery(userQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error('Invalid user credentials.'))
      } else {
        sub = result[0][0].username
      }
    })
    .then(() => {
      return datastore.runQuery(clientQuery)
    })
    .then(result => {
      if (!redirectUriCheck(result, req.body.redirect_uri)) {
        return Promise.reject(new Error('Invalid client and/or redirect URL.'))
      }
    })
    .then(() => {
      const authorizationCode = fernetToken
        .encode(JSON.stringify({
          'client_id': req.body.client_id,
          'redirect_url': req.body.redirect_uri
        }))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')

      const exp = Date.now() + (CODE_LIFE_SPAN * 1000);

      const codeKey = datastore.key(['authorization_code', authorizationCode])
      const data = {
        client_id: req.body.client_id,
        redirect_url: req.body.redirect_uri,
        exp: exp,
        code_challenge: req.body.code_challenge,
        state: req.body?.state || undefined,
        nonce: req.body?.nonce || undefined,
        scope: req.body?.scope || undefined,
        sub,
        email: sub + '@' + (config.maildomain || 'oauth2.local'),

        xumm_payload: req.body?.xumm_payload || undefined,
        xumm_app_usertoken: req.body?.xumm_app_usertoken || undefined,
        xumm_app_name: req.body?.xumm_app_name || undefined, // TODO: Redundant, can be fetched from API or at Client level (view)
      };

      return Promise.all([
        datastore.upsert({ key: codeKey, data: data }),
        Promise.resolve(authorizationCode)
      ])
    })
    .then(results => {
      const responseParams = {
        authorization_code: results[1],
        code: results[1],
        state: req.body?.state || undefined,
        nonce: req.body?.nonce || undefined,
      }

      const fullUrl = appendQuery(req.body.redirect_uri, responseParams)

      if ((req.body?.scope || '').toLowerCase() === 'xummpkce') {
        return renderPkceRedirect(req, res, {
          redirect_uri: req.body.redirect_uri,
          full_redirect_uri: fullUrl,
          ...responseParams
        })
      }

      res.redirect(fullUrl)
    })
}
