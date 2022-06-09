const path = require('path')

module.exports = async function renderPkceRedirect (req, res, options) {
  const html = `
    <!-- <pre>${JSON.stringify(options, null, 2)}</pre> -->
    <!-- <br /><br /> -->
    <!-- Return URL: ${options?.redirect_uri} -->

    <textarea id="pkce_options" style="display: none;">${encodeURIComponent(JSON.stringify(options))}</textarea>

    <pre id="redirecting">Redirecting to Xumm...</pre>
    <pre id="redirected" style="display: none;">Redirected to Xumm...</pre>

    <script target_uri="${options?.redirect_uri}" src="/assets/xumm-pkce.js"></script>
    `.trim()

  res.status(200).send(html)
}
