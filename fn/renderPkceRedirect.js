const path = require('path')

module.exports = async function renderPkceRedirect (req, res, options) {
  const html = `
    <pre>${JSON.stringify(options, null, 2)}</pre>
    <br /><br />
    Return URL: ${options?.redirect_uri}

    <script>
      var options = ${JSON.stringify(options)};
      if (window.opener) {
        if (typeof options.authorization_code === 'string') {
          console.log('Accepted', options)
        } else {
          console.log('Rejected', options)
        }
      } else {
        console.log('Origin window gone?', options?.full_redirect_uri)
      }
    </script>
  `.trim()

  res.status(200).send(html)
}
