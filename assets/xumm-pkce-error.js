if (window.opener) {
  window.onbeforeunload = function () {
    // Nope, not required, window close is expected
    // console.log('Before Unload (error)')
    // window.opener.postMessage(JSON.stringify({
    //   source: 'xumm_sign_request_popup_closed',
    // }), '*')
  }
}
