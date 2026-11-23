// Last resort for an error that no handler caught: one log line with the error text and the place in the code
// (nothing of a request).
const oneLine = error => {
  try {
    return String(error?.stack || error).split('\n').slice(0, 4).map(line => line.trim()).join(' | ').slice(0, 1000)
  } catch (e) {
    return 'unknown error'
  }
}

module.exports = function installProcessErrorHandlers () {
  // A promise that was rejected without a catch: logged, the service keeps running. (Without this handler such a
  // rejection ends the process.)
  process.on('unhandledRejection', reason => {
    console.error('unhandledRejection: ' + oneLine(reason))
  })

  // An error outside every handler: the state of the process is not known. Logged, then the process ends with
  // code 1, as without this handler: the process manager starts it again.
  process.on('uncaughtException', error => {
    console.error('uncaughtException: ' + oneLine(error))
    process.exit(1)
  })
}

Object.assign(module.exports, { oneLine })
