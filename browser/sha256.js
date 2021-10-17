"use strict";

const rawSha256 = require("crypto-digest-sync/sha256");
const SRPInteger = require("../lib/srp-integer");

function bufferToHex(buffer) {
  let hex = "";
  const array = new Uint8Array(buffer);

  for (let i = 0; i < array.length; i++) {
    const value = array[i].toString(16);
    hex += value.length === 1 ? "0" + value : value;
  }

  return hex;
}

function hexToBuffer(hex) {
  hex = hex.length % 2 !== 0 ? "0" + hex : hex;
  const array = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return array.buffer;
}

const encodeUtf8 = TextEncoder.prototype.encode.bind(new TextEncoder());

function concat(buffers) {
  const length = buffers.reduce((mem, item) => mem + item.byteLength, 0);
  const combined = new Uint8Array(length);

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset);
    return offset + item.byteLength;
  }, 0);

  return combined.buffer;
}

/**
 * @param {(string | SRPInteger)[]} args
 */
module.exports = function sha256(...args) {
  const buffer = concat(
    args.map((arg) => {
      if (arg instanceof SRPInteger) {
        return hexToBuffer(arg.toHex());
      } else if (typeof arg === "string") {
        return encodeUtf8(arg);
      } else {
        throw new TypeError("Expected string or SRPInteger");
      }
    }),
  );

  return SRPInteger.fromHex(bufferToHex(rawSha256(buffer)));
};
