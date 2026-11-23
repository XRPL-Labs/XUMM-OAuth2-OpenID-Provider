module.exports = function sanitizeRedirectUri(url) {
  return url
    .replace(/^([a-z0-9]+:\/\/[^?#]+)[?#]*[\s\S]*/, '$1')
    .replace(/\/+$/, '')
}
