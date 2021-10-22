import { HashAlgorithm } from "./types";
import { encodeUtf8 } from "./utils";

const webcrypto: Crypto | undefined =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

const unavailableErrorMessage =
  "WebCrypto is only available on Node.js 15+ and supported browsers (in secure context)";

export const hashBytes: Record<HashAlgorithm, number> = {
  "SHA-1": 160 / 8,
  "SHA-256": 256 / 8,
  "SHA-384": 384 / 8,
  "SHA-512": 512 / 8,
};

// From https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
const pbkdf2Iterations: Record<HashAlgorithm, number> = {
  "SHA-1": 720000,
  "SHA-256": 310000,
  "SHA-384": 215000,
  "SHA-512": 120000,
};

export const getRandomValues = (array: Uint8Array): void => {
  webcrypto && webcrypto.getRandomValues(array);
};

export const digest = (
  hashAlgorithm: HashAlgorithm,
  data: ArrayBuffer,
): Promise<ArrayBuffer> =>
  !webcrypto || !webcrypto.subtle
    ? Promise.reject(new Error(unavailableErrorMessage))
    : webcrypto.subtle.digest(hashAlgorithm, data);

export const deriveKeyWithPBKDF2 = async (
  hashAlgorithm: HashAlgorithm,
  salt: ArrayBuffer,
  password: string,
  iterations = pbkdf2Iterations[hashAlgorithm],
): Promise<ArrayBuffer> => {
  if (!webcrypto || !webcrypto.subtle) {
    throw new Error(unavailableErrorMessage);
  }

  const pbkdf2Key = await webcrypto.subtle.importKey(
    "raw",
    encodeUtf8(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const aesGcmKey = await webcrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: hashAlgorithm,
      salt,
      iterations,
    },
    pbkdf2Key,
    // We don't actually need a cipher suite but the API requires that it must be specified.
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  return webcrypto.subtle.exportKey("raw", aesGcmKey);
};
