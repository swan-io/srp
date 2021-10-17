import { HashAlgorithm } from "./types";

const webcrypto: Crypto | undefined =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

export const hashBytes: Record<HashAlgorithm, number> = {
  "SHA-1": 160 / 8,
  "SHA-256": 256 / 8,
  "SHA-384": 384 / 8,
  "SHA-512": 512 / 8,
};

export const getRandomValues = (array: Uint8Array): void => {
  webcrypto && webcrypto.getRandomValues(array);
};

export const digest = (
  hashAlgorithm: HashAlgorithm,
  data: ArrayBuffer,
): Promise<ArrayBuffer> =>
  webcrypto && webcrypto.subtle
    ? webcrypto.subtle.digest(hashAlgorithm, data)
    : Promise.reject(
        new Error(
          "WebCrypto is only available on Node.js 15+ and supported browsers (in secure context)",
        ),
      );
