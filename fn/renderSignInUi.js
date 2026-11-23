const path = require('path')
const pug = require('pug')
const {datastore} = require('../datastore')
const returnError = require('./returnError')
const {initiateXummSignin} = require('./xummSignin')
const {authStartLimit, callerAddress} = require('./authStartLimit')

async function getClientDetails (client_id) {
  try {
    const results = await datastore.runQuery(datastore.createQuery('client').filter('client-id', '=', client_id))

    if (Array.isArray(results) && results.length > 0 && Array.isArray(results[0]) && results[0].length === 1) {
      return results[0][0]
    }

    throw new Error('Could not fetch Client ID')
  } catch (e) {
    console.log('Render Sign UI error, getClient Details (DB)', e)
    return {error_type: 'get_client_error'}
  }
}

module.exports = async function renderSignInUi (req, res, options) {
  const clientDetails = await getClientDetails(req.query.client_id)

  if (!clientDetails?.['signin-method']) {
    return returnError(req, res, clientDetails?.error_type, 'Invalid client / unknown client_id.', 500, {})
  }

  // console.log('signin-method', clientDetails, clientDetails['signin-method'])

  if (clientDetails['signin-method'] === 'XUMMAPI') {
    // The limit on sign-in starts, after all checks of the request and before the sign request is created. The key
    // is the client id as it is stored: one count per client, whatever the spelling in the request.
    const clientId = String(clientDetails['client-id'] ?? req.query.client_id)
    const limit = authStartLimit.take(callerAddress(req), clientId)
    if (!limit.allowed) {
      console.log('auth: start limit reached, per ' + limit.limit, clientId)
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))))
      return returnError(req, res, 'too_many_requests', 'Too many sign in requests. Please try again in a minute.', 429, {})
    }

    try {
      return initiateXummSignin(req, res)
    } catch (e) {
      return returnError(req, res, 'xaman_api_catch', e.message, 503, {})
    }
  }

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
