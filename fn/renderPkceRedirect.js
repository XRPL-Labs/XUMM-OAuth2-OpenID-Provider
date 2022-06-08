const path = require('path')

module.exports = async function renderPkceRedirect (req, res, options) {
  const html = `
    <pre>${JSON.stringify(options, null, 2)}</pre>
    <br /><br />
    Return URL: ${options?.redirect_uri}
  `.trim()

  res.status(200).send(html)
}
