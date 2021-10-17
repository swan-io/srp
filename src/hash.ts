import { digest } from "./crypto";
import { SRPInt } from "./SRPInt";
import { bufferToHex, hexToBuffer } from "./utils";

const encodeUtf8 = TextEncoder.prototype.encode.bind(new TextEncoder());

export const hash = async (
  algorithm: "SHA-1" | "SHA-256",
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

  return SRPInt.fromHex(bufferToHex(await digest(algorithm, combined.buffer)));
};
