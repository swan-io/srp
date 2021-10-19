import { HashAlgorithm } from ".";
import { digest } from "./crypto";
import { SRPInt } from "./SRPInt";

export const encodeUtf8 = TextEncoder.prototype.encode.bind(new TextEncoder());

export const bufferToHex = (buffer: ArrayBuffer): string => {
  const array = new Uint8Array(buffer);
  let hex = "";

  for (let i = 0; i < array.length; i++) {
    hex += array[i].toString(16).padStart(2, "0");
  }

  return hex;
};

export const hexToBuffer = (hex: string): ArrayBuffer => {
  if (hex.length % 2 !== 0) {
    throw new RangeError("Expected string to be an even number of characters");
  }

  const array = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return array.buffer;
};

export const hash = async (
  hashAlgorithm: HashAlgorithm,
  ...input: (SRPInt | string)[]
) => {
  const buffers = input.map((item) =>
    typeof item === "string" ? encodeUtf8(item) : hexToBuffer(item.toHex()),
  );

  const combined = new Uint8Array(
    buffers.reduce((offset, item) => offset + item.byteLength, 0),
  );

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset);
    return offset + item.byteLength;
  }, 0);

  return SRPInt.fromHex(
    bufferToHex(await digest(hashAlgorithm, combined.buffer)),
  );
};
