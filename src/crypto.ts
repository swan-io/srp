const webcrypto: Crypto | undefined =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

export const getRandomValues = (array: Uint8Array): void => {
  webcrypto && webcrypto.getRandomValues(array);
};

export const digest = (
  algorithm: "SHA-1" | "SHA-256",
  data: ArrayBuffer,
): Promise<ArrayBuffer> =>
  webcrypto && webcrypto.subtle
    ? webcrypto.subtle.digest(algorithm, data)
    : Promise.reject(
        new Error(
          "WebCrypto is only available on Node.js 15+ and supported browsers (in secure context)",
        ),
      );
