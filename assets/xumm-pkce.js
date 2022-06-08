var pkce_options = document.getElementById('pkce_options')
if (pkce_options) {
  try {
    var options = JSON.parse(decodeURIComponent(pkce_options.innerText))
    if (window.opener) {
      if (typeof options.authorization_code === 'string') {
        console.log('Accepted', options)
        window.opener.postMessage(JSON.stringify({
          source: 'xumm_sign_request_resolved',
          options: options
        }), '*')
        setTimeout(function () {
          window.close()
        }, 1)
      } else {
        console.log('Rejected', options)
        window.opener.postMessage(JSON.stringify({
          source: 'xumm_sign_request_rejected',
          options: options
        }), '*')
        setTimeout(function () {
          window.close()
        }, 1)
      }
    } else {
      console.log('Origin window gone?', options.full_redirect_uri)
      if (typeof options.full_redirect_uri === 'string') {
        document.location.href = options.full_redirect_uri
      }
    }
  } catch (e) {
    console.log(e)
  }
}
