const path = require('path')
const pug = require('pug')

module.exports = function returnError (req, res, type, message, code, details) {
  if (req.server2server)  {
    // JSON
    res.status(typeof code === 'number' ? code : 500).json({
      error: typeof type === 'string' ? type : 'unknown',
      error_description: typeof message === 'string' ? message : 'unexpected, unhandled error'
    })
  } else {
    // HTML
    const html = pug.renderFile(path.join(__dirname, '..', 'error.pug'), {
      error_type: typeof type === 'string' ? type : undefined,
      error_message: typeof message === 'string' ? message : 'Invalid client / unknown client_id'
    })

    return res.status(typeof code === 'number' ? code : 500).send(html)
  }
}