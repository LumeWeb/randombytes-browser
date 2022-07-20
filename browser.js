"use strict";

// limit of Crypto.getRandomValues()
// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
var MAX_BYTES = 65536;

// Node supports requesting up to this number of bytes
// https://github.com/nodejs/node/blob/master/lib/internal/crypto/random.js#L48
var MAX_UINT32 = 4294967295;

function oldBrowser() {
  throw new Error(
    "Secure random number generation is not supported by this browser.\nUse Chrome, Firefox or Internet Explorer 11"
  );
}

var crypto =
  typeof global !== "undefined"
    ? global?.crypto || global?.msCrypto
    : self?.crypto;

if (crypto && crypto.getRandomValues) {
  module.exports = randomBytes;
} else {
  module.exports = oldBrowser;
}

function randomBytes(size, cb) {
  // phantomjs needs to throw
  if (size > MAX_UINT32)
    throw new RangeError("requested too many random bytes");

  var bytes = new Uint32Array(size);

  if (size > 0) {
    // getRandomValues fails on IE if size == 0
    if (size > MAX_BYTES) {
      // this is the max bytes crypto.getRandomValues
      // can do at once see https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
      for (var generated = 0; generated < size; generated += MAX_BYTES) {
        // buffer.slice automatically checks if the end is past the end of
        // the buffer so we don't have to here
        crypto.getRandomValues(bytes.slice(generated, generated + MAX_BYTES));
      }
    } else {
      crypto.getRandomValues(bytes);
    }
  }

  bytes.copy = bufferCopy;

  if (typeof cb === "function") {
    return process.nextTick(function () {
      cb(null, bytes);
    });
  }

  return bytes;
}

const bufferCopy = function copy(target, targetStart, start, end) {
  if (!start) start = 0;
  if (!end && end !== 0) end = this.length;
  if (targetStart >= target.length) targetStart = target.length;
  if (!targetStart) targetStart = 0;
  if (end > 0 && end < start) end = start;

  // Copy 0 bytes; we're done
  if (end === start) return 0;
  if (target.length === 0 || this.length === 0) return 0;

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError("targetStart out of bounds");
  }
  if (start < 0 || start >= this.length)
    throw new RangeError("Index out of range");
  if (end < 0) throw new RangeError("sourceEnd out of bounds");

  // Are we oob?
  if (end > this.length) end = this.length;
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start;
  }

  const len = end - start;

  if (
    this === target &&
    typeof Uint8Array.prototype.copyWithin === "function"
  ) {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end);
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    );
  }

  return len;
};
