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
    name: 'Wietse',
  })
})

app.use('/auth', auth)
app.use('/signin', signin)
app.use('/token', token)

app.listen(config.port, () => {
  console.log(`Service listening at :${config.port}`)
})
