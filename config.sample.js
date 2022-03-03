const fs = require('fs')

module.exports = {
  port: 9000,
  secret: 'xxx', // dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64
  db: {
    uri: 'mysql://xxx:xxx@localhost:111/oauth2?charset=utf8mb4',
  },
  jwt: {
    ISSUER: 'xxx',
    JWT_LIFE_SPAN: 1800 * 1000,
    CODE_LIFE_SPAN: 600 * 1000,
    PRIVATE_KEY: fs.readFileSync('private.pem', 'utf8')
  }
}
