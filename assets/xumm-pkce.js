var pkce_options = document.getElementById('pkce_options')
var target_uri = document.querySelector('script[target_uri]').getAttribute('target_uri')

var redirecting = document.getElementById('redirecting')
var redirected = document.getElementById('redirected')

if (pkce_options) {
  try {
    var options = JSON.parse(decodeURIComponent(pkce_options.innerText))
    if (window.opener) {
      window.onbeforeunload = function () {
        // Nope, not required, window close is expected
        // console.log('Before Unload', options)
        // window.opener.postMessage(JSON.stringify({
        //   source: 'xumm_sign_request_popup_closed',
        //   options: options
        // }), target_uri)
      }
      if (typeof options.authorization_code === 'string' || typeof options.access_token === 'string') {
        console.log('Accepted', options)
        window.opener.postMessage(JSON.stringify({
          source: 'xumm_sign_request_resolved',
          options: options
        }), target_uri)
        setTimeout(function () {
          window.close()
        }, 1)
      } else {
        console.log('Rejected', options)
        window.opener.postMessage(JSON.stringify({
          source: 'xumm_sign_request_rejected',
          options: options
        }), target_uri)
        setTimeout(function () {
          window.close()
        }, 1)
      }
    } else {
      console.log('Origin window gone?', options.full_redirect_uri)
      if (typeof options.full_redirect_uri === 'string') {
        document.location.href = options.full_redirect_uri
        if (redirecting) {
          redirecting.style.display = 'none'
        }
        if (redirected) {
          redirected.style.display = 'block'
        }
      }
    }
  } catch (e) {
    console.log(e)
  }
}
