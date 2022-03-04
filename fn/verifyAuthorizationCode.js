const crypto = require('crypto')
const datastore = require('../datastore')

module.exports = function verifyAuthorizationCode (authorizationCode, clientId, redirectUrl, codeVerifier = undefined) {
  console.log('verifyAuthorizationCode')
  const transaction = datastore.transaction()
  const key = datastore.key(['authorization_code', authorizationCode])

  return transaction
    .run()
    .then(() => transaction.get(key))
    .then(result => {
      const entry = result[0]

      if (entry === undefined) {
        return Promise.reject(new Error('Invalid authorization code.'))
      }

      if (entry.client_id !== clientId) {
        return Promise.reject(new Error('Client ID does not match the record.'))
      }

      if (entry.redirect_url !== redirectUrl) {
        return Promise.reject(new Error('Redirect URL does not match the record.'))
      }

      if (entry.exp <= Date.now()) {
        return Promise.reject(new Error('Authorization code expired.'))
      }

      if (codeVerifier !== undefined &&
          entry.code_challenge !== undefined) {
        let codeVerifierBuffer = Buffer.from(codeVerifier)
        let codeChallenge = crypto
                              .createHash('sha256')
                              .update(codeVerifierBuffer)
                              .digest()
                              .toString('base64')
                              .replace(/\+/g, '-')
                              .replace(/\//g, '_')
                              .replace(/=/g, '')
        if (codeChallenge !== entry.code_challenge) {
          return Promise.reject(new Error('Code verifier does not match code challenge.'))
        }
      } else if (codeVerifier === undefined || entry.code_challenge === undefined) {
        // Pass
      } else {
        return Promise.reject(new Error('Code challenge or code verifier does not exist.'))
      }

      transaction.delete(key)

      return entry
    })
    .then(entry => {
      transaction.commit()
      return entry
    })
    .catch(error => {
      console.log({error})
      transaction.rollback()
      throw error
    })
}
