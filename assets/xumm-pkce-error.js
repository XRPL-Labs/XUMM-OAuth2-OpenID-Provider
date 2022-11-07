if (window.opener) {
  window.onbeforeunload = function () {
    console.log('Before Unload (error)')
    window.opener.postMessage(JSON.stringify({
      source: 'xumm_sign_request_popup_closed',
    }), '*')
  }
}
