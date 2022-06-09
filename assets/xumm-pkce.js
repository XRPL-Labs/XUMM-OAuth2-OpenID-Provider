var pkce_options = document.getElementById('pkce_options')
var target_uri = document.querySelector('script[target_uri]').getAttribute('target_uri')

var redirecting = document.getElementById('redirecting')
var redirected = document.getElementById('redirected')

if (pkce_options) {
  try {
    var options = JSON.parse(decodeURIComponent(pkce_options.innerText))
    if (window.opener) {
      if (typeof options.authorization_code === 'string') {
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
        if (redirecting) {
          redirecting.style.display = 'none'
        }
        if (redirected) {
          redirected.setAttribute('style', '')
          redirected.style.display = 'block'
        }
        setTimeout(function () {
          document.location.href = options.full_redirect_uri
        }, 1)
      }
    }
  } catch (e) {
    console.log(e)
  }
}
