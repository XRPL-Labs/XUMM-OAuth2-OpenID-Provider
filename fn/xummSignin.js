const config = require('../config')
const appendQuery = require('append-query')
const returnError = require('./returnError')
const {XummSdk} = require('xumm-sdk')
const {datastore} = require('../datastore')
const crypto = require("crypto")
const oauthErrorRedirect = require('./oauthErrorRedirect')
const renderPkceRedirect = require('./renderPkceRedirect')
const signinInstruction = require('./signinInstruction')

const genHash = function genHash (client, token) {
  const _token = token || crypto.randomBytes(12).toString('hex')
  const tokenhash = crypto.createHash('sha256').update(_token + client + config.secret).digest('hex').slice(0, 20)
  return { token: _token, hash: tokenhash }
}

// A sign-in gives its result only shortly after the user resolved the sign request (SIGNIN_MAX_AGE_MS), and a few
// times at most (SIGNIN_MAX_USES): the same return comes more than once when the browser has it in two tabs or
// loads it again. Every use after the first must come within SIGNIN_REUSE_MS after the first.
const SIGNIN_MAX_USES = 4
const SIGNIN_REUSE_MS = 180 * 1000
const SIGNIN_MAX_AGE_MS = 10 * 60 * 1000

// The uses of a sign-in are kept in its challenge row:
//   consumed NULL or 0   not used
//   consumed 10 + n      used n times: the time of the first use (ms) is `__used_at` in params
//   consumed 1           a row that was used when the uses were not counted: no use left
// Any other value: no use left.
const SIGNIN_USED_BASE = 10

// How often the sign-in was used, when it has a use left at this moment. No use left: undefined.
const signinUsesSoFar = function signinUsesSoFar (consumed, usedAt) {
  const state = Number(consumed ?? 0)
  if (state === 0) return 0
  const uses = state - SIGNIN_USED_BASE
  if (Number.isInteger(uses) && uses >= 1 && uses < SIGNIN_MAX_USES && Date.now() - Number(usedAt ?? NaN) <= SIGNIN_REUSE_MS) return uses
}

const sameToken = function sameToken (a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)
}

// Time since the sign request was resolved (ms). Both moments are taken from the API answer when it has them (one
// clock, so a clock or time zone difference between the two hosts does not matter), else this host's clock is used.
// NaN when the answer has no usable resolve time.
const resolvedAgeMs = function resolvedAgeMs (signInResult) {
  const resolvedAt = Date.parse(signInResult?.response?.resolved_at)
  const apiNow = Date.parse(signInResult?.payload?.expires_at) - parseFloat(signInResult?.payload?.expires_in_seconds) * 1000
  return (Number.isFinite(apiNow) ? apiNow : Date.now()) - resolvedAt
}

// Takes one use of the sign-in, in one conditional UPDATE: it matches only while `consumed` still has the value that
// was read, so requests at the same moment never take the same use. A request that was too late reads the row again
// (the value changed, so at most SIGNIN_MAX_USES rounds). Gives the time of the first use (ms), or false: no use left.
const takeSigninUse = async function takeSigninUse (client, payload) {
  const rowQuery = () => datastore.createQuery('xumm_challenge')
    .filter('payload', '=', payload)
    .filter('client', '=', client)

  try {
    for (let round = 0; round < SIGNIN_MAX_USES; round++) {
      const rows = (await datastore.runQuery(rowQuery()))?.[0]
      if (!Array.isArray(rows) || rows.length !== 1) return false

      const consumed = rows[0].consumed ?? null
      const params = JSON.parse(rows[0].params)
      const uses = signinUsesSoFar(consumed, params?.__used_at)
      if (typeof uses === 'undefined') return false

      // The first use also stores its time. A later use only counts: that time stays.
      const usedAt = uses === 0 ? Date.now() : Number(params.__used_at)
      const data = { consumed: SIGNIN_USED_BASE + uses + 1 }
      if (uses === 0) data.params = JSON.stringify({...params, __used_at: usedAt})

      const result = await rowQuery().filter('consumed', '<=>', consumed).update(data)
      if (result?.[0]?.affectedRows === 1) return usedAt
    }

    return false
  } catch (e) {
    console.log('takeSigninUse error', e.message)
    throw new Error('Could not store the Xaman Sign In state')
  }
}

// The answer for a sign-in that gives no result (rejected, used before, too old): the OAuth2 error goes to the
// client, in the way the client asked for its answer.
const signinRefused = async function signinRefused (req, res, challengeData, error_description) {
  const errData = {
    error: 'access_denied',
    error_description
  }
  if ((challengeData?.scope || '').toLowerCase() === 'xummpkce') {
    await renderPkceRedirect(req, res, {
      redirect_uri: challengeData.redirect_uri,
      full_redirect_uri: appendQuery(challengeData.redirect_uri, errData),
      ...errData
    })
    return true
  }
  oauthErrorRedirect(res, challengeData.redirect_uri, errData.error, errData.error_description, challengeData?.state)
  return true
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

      const force_network = String(req.query?.force_network || '').trim().toUpperCase()
      const signers = String(req.query?.signers || '').trim()

      const payload = await Sdk.payload.create({
        options: {
          force_network: force_network.match(/^[A-Z]+$/) ? force_network : undefined,
          signers: signers.match(/^r[a-zA-Z0-9]{10,}/) ? signers.split(',').map(s => s.trim()) : undefined,
          return_url: {
            app: config.openid.discovery.issuer + '/signin?t=' + token + '&h=' + hash + '&c=' + req.query.client_id + '&payload={id}',
            web: config.openid.discovery.issuer + '/signin?t=' + token + '&h=' + hash + '&c=' + req.query.client_id + '&payload={id}'
          }
        },
        custom_meta: {
          instruction: signinInstruction(req.query.redirect_uri)
        },
        txjson: {
          TransactionType: 'SignIn'
        }
      })

      if (payload && typeof payload?.uuid === 'string') {
        // The flow's own token is stored with the challenge (`__t`): the return step must come with the same one.
        // The row is there before the user is sent on.
        try {
          await datastore.upsert({fields: {
            client: req.query.client_id,
            payload: payload.uuid,
            params: JSON.stringify({...req.query, __t: token})
          }})
        } catch (e) {
          console.log('initiateXummSignin: challenge not stored', e.message)
          return returnError(req, res, 'xaman_signin_store_err', 'Could not start the Xaman Sign In', 500, {})
        }

        return res.redirect(payload.next.always)
      }
    } catch (e) {
      return returnError(req, res, 'xaman_api_err', e.message, 503, {})
    }

    // No payload and no error (the Xaman API refused: application disabled, rate limit, ...). This read `e`, which
    // does not exist here: a ReferenceError, no response, the request stayed open (24,733 times in the error log).
    return returnError(req, res, 'xaman_api_final_err', 'Error communicating to the Xaman API', 500, {})
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
              const challengeRow = challengeRecord[0][0]
              const clientId = String(challengeRow.client)
              const payloadId = String(challengeRow.payload)

              // `__t` is the flow's own token (stored at the start), `__used_at` the time of the first use (stored at
              // that use), the rest is the query of the /auth request
              const {__t: flowToken, __used_at: firstUsedAt, ...challengeData} = JSON.parse(challengeRow.params)
              console.log({challengeData})

              // The request must be the return of the flow this sign-in was started in. A row stored before the flow
              // token was kept has none: it only gets the checks below (this exception can go one day after release).
              if (typeof flowToken !== 'undefined' && !sameToken(flowToken, req.query.t)) {
                console.log('Sign in refused: not the token of this flow', clientId, payloadId)
                return returnError(req, res, 'xaman_signin_sec_vil', 'Xaman Sign In: security violation', 403, {})
              }

              // No use left (see signinUsesSoFar): the OAuth2 error, before the API is asked
              if (typeof signinUsesSoFar(challengeRow.consumed, firstUsedAt) === 'undefined') {
                console.log('Sign in refused: used before', clientId, payloadId)
                return signinRefused(req, res, challengeData, 'This sign in has already been used, please sign in again')
              }

              const Sdk = await getSdkByClient(challengeData.client_id)
              const signInResult = await Sdk.payload.get(payloadId)
              const account = signInResult?.response?.account

              if (!signInResult?.meta?.signed || !account) {
                return signinRefused(req, res, challengeData, 'The XUMM sign in request has been rejected')
              }

              const resolvedAge = resolvedAgeMs(signInResult)
              if (!(resolvedAge <= SIGNIN_MAX_AGE_MS)) {
                console.log('Sign in refused: resolved too long ago', clientId, payloadId, Math.round(resolvedAge / 1000))
                return signinRefused(req, res, challengeData, 'This sign in has expired, please sign in again')
              }

              console.log('Signed SDK result from: ', payloadId, account)

              const password = crypto.createHash('sha256').update(account + config.secret).digest('hex')

              await datastore.upsert({xrpluser: {
                username: account,
                password,
                xrpl_account: 1
              }})

              const signinUsedAt = await takeSigninUse(clientId, payloadId)
              if (!signinUsedAt) {
                console.log('Sign in refused: no use left', clientId, payloadId)
                return signinRefused(req, res, challengeData, 'This sign in has already been used, please sign in again')
              }

              // The token or code of every use counts its lifetime from the first use. Set here only, never by the
              // request.
              req.xummSigninUsedAt = signinUsedAt

              // The sign-in data: the stored challenge and the result of the sign request only. Nothing of the body
              // or the query of this request is kept.
              req.body = {
                ...challengeData,
                username: account,

                xumm_payload: payloadId,
                xumm_app_uuid: signInResult?.application?.uuidv4,
                xumm_app_usertoken: signInResult?.application?.issued_user_token,
                xumm_app_name: signInResult?.application?.name,

                xumm_network_type: signInResult?.response?.environment_nodetype,
                xumm_network_endpoint: signInResult?.response?.environment_nodeuri,
                xumm_network_id: String(signInResult?.response?.environment_networkid), // cast to string, SQL turns it into INT, force `0`

                password,
              }

              // Debug
              // return res.json({worked: true, account, payload: req.query.payload, client: req.query.t, challengeData}) 
              return
            }
          } else {
            return returnError(req, res, 'xaman_signin_sec_vil', 'Xaman Sign In: security violation', 403, {})
          }
        }

        return returnError(req, res, 'xaman_signin_redir_err', 'Could not resolve Xaman Sign In details', 500, {})
      }
      
      return
    } catch (e) {
      return returnError(req, res, 'handle_signin_fatal', e.message, 500, {})
    }
  }
}
