const path = require('path')
const pug = require('pug')
const {db} = require('../datastore')
const returnError = require('./returnError')

async function getClientDetails (client_id) {
  try {
    const conn = await db.getConnection()
    const results = await conn.execute('SELECT `signin-method` FROM clients WHERE `client-id` = ? LIMIT 1', [client_id])

    conn.release()

    if (Array.isArray(results) && results.length > 0 && Array.isArray(results[0]) && results[0].length === 1) {
      return results[0][0]
    }

    throw new Error('Could not fetch Client ID')
  } catch (e) {
    console.log('Render Sign UI error, getClient Details (DB)', e)
    try { conn.release() } catch (e) {}
    return {error_type: 'get_client_error'}
  }
}

module.exports = async function renderSignInUi (req, res, options) {
  const clientDetails = await getClientDetails(req.query.client_id)

  if (!clientDetails?.['signin-method']) {
    return returnError(req, res, clientDetails?.error_typ, 'Invalid client / unknown client_id.', 500, {})
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
