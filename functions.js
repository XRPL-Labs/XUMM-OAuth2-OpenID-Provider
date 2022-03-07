const handleACPKCEAuthRequest = require('./fn/handleACPKCEAuthRequest')
const handleACAuthRequest = require('./fn/handleACAuthRequest')
const handleImplicitAuthRequest = require('./fn/handleImplicitAuthRequest')
const handleACPKCESigninRequest = require('./fn/handleACPKCESigninRequest')
const handleACSigninRequest = require('./fn/handleACSigninRequest')
const handleImplictSigninRequest = require('./fn/handleImplictSigninRequest')
const handleROPCTokenRequest = require('./fn/handleROPCTokenRequest')
const handleACTokenRequest = require('./fn/handleACTokenRequest')
const handleACPKCETokenRequest = require('./fn/handleACPKCETokenRequest')
const handleCCTokenRequest = require('./fn/handleCCTokenRequest')
const returnError = require('./fn/returnError')

module.exports = {
  auth (req, res) {
    console.log('auth')
  
    switch (req.query.response_type) {
      case ('code'):
        if (req.query.code_challenge && req.query.code_challenge_method) {
          handleACPKCEAuthRequest(req, res)
        } else if (!req.query.code_challenge && !req.query.code_challenge_method) {
          handleACAuthRequest(req, res)
        } else {
          returnError(req, res, 'invalid_request', 'Required parameters are missing in the request.', 400, {})
        }

        break
  
      case ('token'):
        handleImplicitAuthRequest(req, res)

        break
  
      default:
        returnError(req, res, 'invalid_request', 'Grant type is invalid or missing.', 400, {})

        break
    }
  },
  token (req, res) {
    // If BASIC auth, mock client_id and client_secret
    const b64auth = ((req.headers?.authorization || '').trim() || '').split(' ').reverse()[0] || ''
    const strauth = Buffer.from(b64auth, 'base64').toString()
    const splitIndex = strauth.indexOf(':')
    console.log({b64auth, strauth, splitIndex})

    let login
    let password
    if (splitIndex > -1 && !req.body?.client_id && !req.body?.client_secret) {
      login = strauth.substring(0, splitIndex)
      password = strauth.substring(splitIndex + 1)
      // console.log({login, password})
      req.body.client_id = login
      req.body.client_secret = password
    }

    switch (req.body.grant_type) {
      case 'password':
        handleROPCTokenRequest(req, res)
      break
  
      case 'authorization_code':
        if (req.body.client_secret && !req.body.code_verifier) {
          handleACTokenRequest(req, res)
          break
        }
        if (req.body.code_verifier) {
          handleACPKCETokenRequest(req, res)
          break
        }

        returnError(req, res, 'invalid_request', 'Client secret and code verifier are exclusive to each other.', 400, {})
      break
  
      case 'client_credentials':
        handleCCTokenRequest(req, res)
      break
  
      default:
        returnError(req, res, 'invalid_request', 'Grant type is invalid or missing.', 400, {})
      break
    }
  },
  signin (req, res) {
    switch (req?.body?.response_type ? req.body.response_type : req?.query?.response_type) {
      case ('code'):
        if (!req.body.code_challenge) {
          handleACSigninRequest(req, res)
        } else {
          handleACPKCESigninRequest(req, res)
        }
        break
  
      case ('token'):
        handleImplictSigninRequest(req, res)
        break
  
      default:
        returnError(req, res, 'invalid_request', 'Grant type is invalid or missing.', 400, {})
        break
    }
  }
}
