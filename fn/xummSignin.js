const config = require('../config')
const returnError = require('./returnError')
const {XummSdk} = require('xumm-sdk')
const {datastore} = require('../datastore')
const crypto = require("crypto")
const oauthErrorRedirect = require('./oauthErrorRedirect')
const renderPkceRedirect = require('./renderPkceRedirect')

const genHash = function genHash (client, token) {
  const _token = token || crypto.randomBytes(12).toString('hex')
  const tokenhash = crypto.createHash('sha256').update(_token + client + config.secret).digest('hex').slice(0, 20)
  return { token: _token, hash: tokenhash }
}

const getSdkByClient = async function getSdkByClient (client) {
  const sdkClientQuery = datastore.createQuery('client')
    .filter('client-id', '=', client)

  const sdkClientRecord = await datastore.runQuery(sdkClientQuery)

  if (Array.isArray(sdkClientRecord) && sdkClientRecord.length > 0) {
    if (Array.isArray(sdkClientRecord[0]) && sdkClientRecord[0].length > 0) {
      return new XummSdk(sdkClientRecord[0][0]['client-id'], sdkClientRecord[0][0]['client-secret'])
    }
  }

  return new XummSdk('---', '---')
}

module.exports = {
  initiateXummSignin: async function initiateXummSignin (req, res) {
    try {
      const Sdk = await getSdkByClient(req.query.client_id)
      const {token, hash} = genHash(req.query.client_id)

      const payload = await Sdk.payload.create({
        options: {
          return_url: {
            app: config.openid.discovery.issuer + '/signin?t=' + token + '&h=' + hash + '&c=' + req.query.client_id + '&payload={id}',
            web: config.openid.discovery.issuer + '/signin?t=' + token + '&h=' + hash + '&c=' + req.query.client_id + '&payload={id}'
          }
        },
        custom_meta: {
          instruction: 'Sign in to ' + req.query.redirect_uri.replace(/^[a-z0-9]+:\/\//, '').split('/')[0]
        },
        txjson: {
          TransactionType: 'SignIn'
        }
      })

      if (payload && typeof payload?.uuid === 'string') {
        datastore.upsert({fields: {
          client: req.query.client_id,
          payload: payload.uuid,
          params: JSON.stringify(req.query)
        }})

        return res.redirect(payload.next.always)
      }
    } catch (e) {
      return returnError(req, res, 'xumm_api_err', e.message, 503, {})
    }

    return returnError(req, res, 'xumm_api_final_err', 'Error communicating to the XUMM API', 500, {})
  },
  handleXummSignin: async function handleXummSignin (req, res) {
    try {
      if (req.query?.payload) {
        if (req.query?.t && req.query?.h && req.query?.c) {
          const {token, hash} = genHash(req.query.c, req.query.t)

          // const results = await datastore.runQuery(datastore.createQuery('client').filter('client-id', '=', client_id))
          // if (Array.isArray(results) && results.length > 0 && Array.isArray(results[0]) && results[0].length === 1) {
          //   return results[0][0]
          // }

          if (token === req.query.t && hash === req.query.h) {
            const challengeQuery = datastore.createQuery('xumm_challenge')
              .filter('payload', '=', req.query.payload)
              .filter('client', '=', req.query.c)

            const challengeRecord = await datastore.runQuery(challengeQuery)
            if (Array.isArray(challengeRecord) && challengeRecord.length > 0 && Array.isArray(challengeRecord[0]) && challengeRecord[0].length === 1) {
              const challengeData = JSON.parse(challengeRecord[0][0].params)
              console.log({challengeData})

              // No need, a grant can only be fetched once
              //
              // if (challengeRecord[0][0].consumed > 0) {
              //   return !!oauthErrorRedirect(res, challengeData.redirect_uri, 'temporarily_unavailable', 'This XUMM sign in flow has already been consumed')
              // }

              datastore.updateQuery(challengeQuery, { consumed: 1 })

              const Sdk = await getSdkByClient(challengeData.client_id)
              const signInResult = await Sdk.payload.get(req.query.payload)
              const account = signInResult?.response?.account
              const password = crypto.createHash('sha256').update(account + config.secret).digest('hex')

              if (!signInResult?.meta?.signed || !account) {
                // TODO: Check scope, if challengeData.scope.toLowerCase() === 'xummpkce' » JS redirect
                if ((challengeData?.scope || '').toLowerCase() === 'xummpkce') {
                  return renderPkceRedirect(req, res, {
                    redirect_uri: challengeData.redirect_uri
                  })
                }
                return !!oauthErrorRedirect(res, challengeData.redirect_uri, 'access_denied', 'The XUMM sign in request has been rejected')
              }

              console.log('Signed SDK result from: ', req.query.payload, account)

              Object.assign(req.body, {
                ...challengeData,
                username: account,

                xumm_payload: req.query.payload,
                xumm_app_uuid: signInResult?.application?.uuidv4,
                xumm_app_usertoken: signInResult?.application?.issued_user_token,
                xumm_app_name: signInResult?.application?.name,

                password,
              })

              await datastore.upsert({xrpluser: {
                username: account,
                password,
                xrpl_account: 1
              }})

              // Debug
              // return res.json({worked: true, account, payload: req.query.payload, client: req.query.t, challengeData}) 
              return
            }
          } else {
            return returnError(req, res, 'xumm_signin_sec_vil', 'XUMM Sign In: security violation', 403, {})
          }
        }

        return returnError(req, res, 'xumm_signin_redir_err', 'Could not resolve XUMM Sign In details', 500, {})
      }
      
      return
    } catch (e) {
      return returnError(req, res, 'handle_signin_fatal', e.message, 500, {})
    }
  }
}
