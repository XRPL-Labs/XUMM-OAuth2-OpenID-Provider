module.exports = function sanitizeRedirectUri(url) {
  return url
    .replace(/^([a-z0-9]+:\/\/[^?#]+)[?#]*.*/, '$1')
    .replace(/\/+$/, '')
}
