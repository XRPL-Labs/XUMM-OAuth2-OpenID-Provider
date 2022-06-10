const config = require('../config')
const appendQuery = require('append-query')
const {datastore} = require('../datastore')
const returnError = require('./returnError')
const fernet = require('fernet')
const redirectUriCheck = require('./redirectUriCheck')

const {CODE_LIFE_SPAN} = config.jwt
const fernetToken = new fernet.Token({ secret: new fernet.Secret(config.secret) })

module.exports = function handleACSigninRequest (req, res) {
  console.log('handleACSigninRequest')

  if (req.body.username === undefined || req.body.password === undefined || req.body.client_id === undefined || req.body.redirect_uri === undefined) {
    return returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
  }

  console.log('acrequest', req.body)

  const userQuery = datastore
    .createQuery('user')
    .filter('username', '=', req.body.username)
    .filter('password', '=', req.body.password)

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    // .filter('redirect-url', 'LIKE', '%' + req.body.redirect_uri + '%')
    .filter('ac-enabled', '=', true)

  let sub = null // username

  datastore
    .runQuery(userQuery)
    .then(result => {
      // DEBUG
      // console.log('sign in userquery result', result)
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

      const key = datastore.key(['authorization_code', authorizationCode])
      const data = {
        client_id: req.body.client_id,
        redirect_url: req.body.redirect_uri,
        exp: exp,
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
        datastore.upsert({ key: key, data: data }),
        Promise.resolve(authorizationCode)
      ])
    })
    .then(results => {
      res.redirect(appendQuery(req.body.redirect_uri, {
        authorization_code: results[1],
        code: results[1],
        state: req.body?.state || undefined,
        nonce: req.body?.nonce || undefined,
      }))
    })
    .catch (e => {
      console.log('error', e.message)
      return returnError(req, res, 'fatal', e.message, 400, {})
    })
}
