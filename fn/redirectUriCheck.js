const sanitizeRedirectUri = require('./sanitizeRedirectUri')

module.exports = function redirectUriCheck(dbresult, uri) {
  if (Array.isArray(dbresult) && dbresult.length > 0) {
    if (Array.isArray(dbresult[0]) && dbresult[0].length > 0) {
      if (dbresult[0][0]?.['redirect-url']) {
        const uris = dbresult[0][0]?.['redirect-url'].trim().split("\n")
          .filter(u => u.match(/^[a-z0-9]{1,}[a-z0-9]{1,}:\//))
          .map(u => sanitizeRedirectUri(u))
        
        const sUri = sanitizeRedirectUri(uri)
        
        console.log({uris, uri, sUri})

        if (uris.filter(u => u === sUri).length > 0) {
          return dbresult
        }
      }
    }
  }

  return false
}
