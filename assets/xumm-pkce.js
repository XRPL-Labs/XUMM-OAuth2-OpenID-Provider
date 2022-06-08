var pkce_options = document.getElementById('pkce_options')
if (pkce_options) {
  try {
    var options = JSON.parse(decodeURIComponent(pkce_options.innerText))
    if (window.opener) {
      if (typeof options.authorization_code === 'string') {
        console.log('Accepted', options)
      } else {
        console.log('Rejected', options)
      }
    } else {
      console.log('Origin window gone?', options?.full_redirect_uri)
    }
  } catch (e) {
    console.log(e)
  }
}
