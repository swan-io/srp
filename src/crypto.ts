const webcrypto: Crypto | undefined =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

export const getRandomValues = (array: Uint8Array): void => {
  webcrypto && webcrypto.getRandomValues(array);
};

export const hash = (data: ArrayBuffer): Promise<ArrayBuffer> =>
  webcrypto && webcrypto.subtle
    ? webcrypto.subtle.digest("SHA-256", data)
    : Promise.reject(
        new Error(
          "WebCrypto is only available on Node.js 15+ and supported browsers (in secure context)",
        ),
      );
