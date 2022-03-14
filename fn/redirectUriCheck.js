module.exports = function redirectUriCheck (dbresult, uri) {
  if (Array.isArray(dbresult) && dbresult.length > 0) {
    if (Array.isArray(dbresult[0]) && dbresult[0].length > 0) {
      if (dbresult[0][0]?.['redirect-url']) {
        const uris = dbresult[0][0]?.['redirect-url'].trim().split("\n")
          .filter(u => u.match(/^https:/))
        
        console.log({uris, uri})

        if (uris.filter(u => u === uri).length > 0) {
          return dbresult
        }
      }
    }
  }

  return false
}
