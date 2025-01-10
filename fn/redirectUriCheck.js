const sanitizeRedirectUri = require('./sanitizeRedirectUri')

function matchWildcardDomain(pattern, uri) {
  // Convert wildcard pattern to regex pattern
  const regexPattern = pattern
    // Escape dots in the domain
    .replace(/\./g, '\\.')
    // Convert wildcard to regex pattern that allows multiple subdomain levels
    .replace(/\*/g, '(?:[a-z0-9-]+\\.)*[a-z0-9-]+');
  
  // Create full regex with start/end anchors
  const regex = new RegExp(`^${regexPattern}$`);
  
  // Extract domain from URI for comparison
  const domain = uri.replace(/^[a-z0-9]+:\/\/([^\/]+).*$/, '$1');
  
  return regex.test(domain);
}

module.exports = function redirectUriCheck(dbresult, uri) {
  if (Array.isArray(dbresult) && dbresult.length > 0) {
    if (Array.isArray(dbresult[0]) && dbresult[0].length > 0) {
      if (dbresult[0][0]?.['redirect-url']) {
        const uris = dbresult[0][0]?.['redirect-url'].trim().split("\n")
          .filter(u => u.match(/^[a-z0-9]{1,}[a-z0-9]{1,}:\//))
          .map(u => sanitizeRedirectUri(u))
        
        const sUri = sanitizeRedirectUri(uri)
        
        // console.log({uris, uri, sUri})
        // if (uris.filter(u => u === sUri.slice(0, u.length)).length > 0) {
        //   return dbresult
        // }

        // Check each allowed URI pattern
        for (const allowedUri of uris) {         
          // If the URI contains a wildcard
          if (allowedUri.includes('*.')) {
            // Extract the domain pattern from the allowed URI
            const domainPattern = allowedUri.replace(/^[a-z0-9]+:\/\//, '');
            // Extract the protocol from the allowed URI
            const protocol = allowedUri.match(/^[a-z0-9]+:\/\//)[0];
            // Check if protocols match and if the domain matches the wildcard pattern
            if (sUri.startsWith(protocol) && matchWildcardDomain(domainPattern, sUri)) {
              return dbresult;
            }
          } else {
            // For non-wildcard URIs, use the original exact matching
            if (uris.filter(u => u === sUri.slice(0, u.length)).length > 0) {
              return dbresult
            }
          }
        }
      }
    }
  }

  return false
}
