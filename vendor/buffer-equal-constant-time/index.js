'use strict'

// Same contract as the package of this name: true only for two buffers with the same bytes, compared in constant
// time. The original reads `SlowBuffer` when it loads, which newer Node versions do not have. This one uses
// crypto.timingSafeEqual.
const crypto = require('crypto')

const bufferEq = function bufferEq (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false
  // The length of a signature is known information
  if (a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

// The original could add an `equal` method to Buffer. Kept as functions that do nothing: no caller here uses them.
bufferEq.install = function () {}
bufferEq.restore = function () {}

module.exports = bufferEq
