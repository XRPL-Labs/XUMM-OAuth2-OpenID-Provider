const jwt = require('jsonwebtoken')
const config = require('./config')
const {ISSUER, PRIVATE_KEY} = config.jwt

const {auth, signin, token} = require('./functions')

const express = require('express')
const helmet = require("helmet")

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

app.use(bodyParser.urlencoded({ extended: false }))

const jwtAuth = (req, res, next) => {
  const authHeader = req.headers?.authorization
  const token = authHeader && authHeader.trim().split(' ').reverse()[0].trim()

  if (token == null) return res.status(401).json({
    error: 'invalid_jwt',
    error_description: 'No JWT token (auth) specified'
  })

  jwt.verify(token, PRIVATE_KEY, {
    algorithms: ['RS256'],
    issuer: ISSUER,
  }, (err, user) => {
    console.log({err: err ? err.message : false, user})

    if (err) return res.status(403).json({
      error: 'jwt_auth_error',
      error_description: err?.message || 'Unspecified',
      details: err
    })

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
  res.json({
    sub: req.user.sub,
    name: 'Wietse Wind',
    picture: 'https://wietse.com/static/nodum/me.png',
    locale: 'en',
   })
})

app.use('/auth', auth)
app.use('/signin', signin)
app.use('/token', token)

app.listen(config.port, () => {
  console.log(`Service listening at :${config.port}`)
})
