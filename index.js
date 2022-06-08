const jwt = require('jsonwebtoken')
const config = require('./config')
const {ISSUER, PRIVATE_KEY} = config.jwt
const returnError = require('./fn/returnError')
const {auth, signin, token} = require('./functions')
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args))

const express = require('express')
const helmet = require('helmet')

const bodyParser = require('body-parser')

const app = express()
app.use(helmet.contentSecurityPolicy({
  directives: {
    formAction: null,
    upgradeInsecureRequests: [],
    scriptSrc: [ "'self'", "https://xumm.app", "https://kit.fontawesome.com" ],
    connectSrc: [ "'self'", "https://xumm.app", "https://kit.fontawesome.com", "https://*.fontawesome.com" ],
    imgSrc: [ "'self'", "https://xumm.app" ],
    styleSrc: [ "'self'", "https://xumm.app", "'unsafe-inline'", "https://fonts.googleapis.com", "https://stackpath.bootstrapcdn.com", "https://kit.fontawesome.com", "https://use.typekit.net", "https://p.typekit.net", "https://*.fontawesome.com" ],
  },
}))
app.use(express.json())

app.use((req, res, next) => {
  if ('OPTIONS' === req.method) {
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.sendStatus(200)
    return res.end('')
  }

  let backendProbability = 0
  const amountOfUsableHeaders = Object.keys(req.headers).filter(k => k.slice(0, 3).toLowerCase() !== 'cf-' && k.slice(0, 2).toLowerCase() !== 'x-').length

  if (amountOfUsableHeaders < 6) backendProbability += 0.4
  if (req.headers?.referer) backendProbability += 0.2
  if (req.headers?.['upgrade-insecure-requests']) backendProbability -= 0.2
  if (req.headers?.['cache-control']) backendProbability -= 0.1
  if (req.headers?.['accept-language']) backendProbability -= 0.1
  if (req.headers?.['sec-fetch-site']) backendProbability -= 0.2
  if ((req.headers?.['user-agent'] || '').match(/mozilla|intel|firefox|gecko|webkit|safari|windows|chrome|x11/i)) backendProbability -= 0.1
  if ((req.headers?.accept || '').match(/application\/json/i)) backendProbability += 0.4
  if ((req.headers?.accept || '').match(/text\/html/i)) backendProbability -= 0.4
  if (req.headers?.accept === '*/*') backendProbability += 0.4

  if (backendProbability >= 0.4) {
    req.server2server = true
  }

  next()
})

app.use(bodyParser.urlencoded({ extended: false }))

const jwtAuth = (req, res, next) => {
  const authHeader = req.headers?.authorization
  const token = authHeader && authHeader.trim().split(' ').reverse()[0].trim()

  if (token == null) return returnError(req, res, 'invalid_jwt', 'No JWT token (auth) specified.', 401, {})

  jwt.verify(token, PRIVATE_KEY, {
    algorithms: ['RS256'],
    issuer: ISSUER,
  }, (err, user) => {
    console.log({err: err ? err.message : false, user})

    if (err) return returnError(req, res, 'jwt_auth_error', err?.message || 'Unspecified', 403, err)

    req.user = user

    next()
  })
}

app.use('/certs', async (req, res) => {
  res.json({keys: config.openid.certs})
})

app.use('/.well-known/openid-configuration', async (req, res) => {
  res.json(config.openid.discovery)
})

app.use('/userinfo', jwtAuth, async (req, res) => {
  const xummInfoCall = await fetch('https://xumm.app/api/v1/app/account-info/' + req.user.sub)
  const xummInfo = await xummInfoCall.json()

  res.json({
    sub: req.user.sub,
    picture: `https://xumm.app/avatar/${req.user.sub}.png`,
    ...(xummInfo?.account ? xummInfo : {}),
   })
})

app.use('/auth', auth)
app.use('/signin', signin)
app.use('/token', token)

app.use('/assets', express.static('./assets'))

app.listen(config.port, () => {
  console.log(`Service listening at :${config.port}`)
})
