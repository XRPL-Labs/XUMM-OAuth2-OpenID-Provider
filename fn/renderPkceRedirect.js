// The redirect URI comes from the request: it went into the page as is (an HTML comment and an attribute), so a
// redirect URI with `-->` or `"` in its path could run script on this origin, on the page that holds the
// authorization code. Now: no comments with request data, the attribute is HTML escaped.
const escapeHtml = v => String(v ?? '').replace(/[&<>"'`]/g, c => '&#' + c.charCodeAt(0) + ';')

module.exports = async function renderPkceRedirect (req, res, options) {
  const html = `
    <textarea id="pkce_options" style="display: none;">${encodeURIComponent(JSON.stringify(options))}</textarea>

    <pre id="redirecting">Redirecting to Xumm...</pre>
    <pre id="redirected" style="display: none;">Redirected to Xumm...</pre>

    <script target_uri="${escapeHtml(options?.redirect_uri)}" src="/assets/xumm-pkce.js?101"></script>
    `.trim()

  res.status(200).send(html)
}

Object.assign(module.exports, { escapeHtml })
