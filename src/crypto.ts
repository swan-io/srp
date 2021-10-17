import { bufferToHex } from "./utils";

const webcrypto: Crypto | undefined =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

export const getRandomHex = (bytes: number) => {
  const array = new Uint8Array(bytes);
  webcrypto && webcrypto.getRandomValues(array);
  return bufferToHex(array);
};

export const hash = (data: ArrayBuffer): Promise<ArrayBuffer> =>
  webcrypto && webcrypto.subtle
    ? webcrypto.subtle.digest("SHA-256", data)
    : Promise.reject(
        new Error(
          "WebCrypto is only available on Node.js 15+ and supported browsers (in secure context)",
        ),
      );
