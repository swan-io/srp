import { deriveKeyWithPBKDF2 } from "./crypto";
import { getParams } from "./params";
import { SRPError } from "./SRPError";
import { SRPInt } from "./SRPInt";
import { Ephemeral, HashAlgorithm, PrimeGroup, Session } from "./types";
import { bufferToHex, hexToBuffer } from "./utils";

export const createSRPClient = (
  hashAlgorithm: HashAlgorithm,
  primeGroup: PrimeGroup,
) => {
  const { N, g, k, H, PAD, hashBytes } = getParams(hashAlgorithm, primeGroup);

  return {
    generateSalt: (): string => {
      const s = SRPInt.getRandom(hashBytes); // User's salt
      return s.toHex();
    },

    derivePrivateKey: async (
      salt: string,
      username: string,
      password: string,
    ): Promise<string> => {
      const s = SRPInt.fromHex(salt); // User's salt
      const I = username.normalize("NFKC"); // Username
      const p = password.normalize("NFKC"); // Cleartext Password

      // x = H(s, H(I | ':' | p))  (s is chosen randomly)
      const x = await H(s, await H(`${I}:${p}`));
      return x.toHex();
    },

    deriveSafePrivateKey: async (
      salt: string,
      password: string,
      iterations?: number,
    ): Promise<string> => {
      const s = hexToBuffer(salt); // User's salt (chosen randomly)
      const p = password.normalize("NFKC"); // Cleartext Password

      return bufferToHex(
        await deriveKeyWithPBKDF2(hashAlgorithm, s, p, iterations),
      );
    },

    deriveVerifier: (privateKey: string): string => {
      const x = SRPInt.fromHex(privateKey); // Private key (derived from p and s)

      // v = g^x  (computes password verifier)
      const v = g.modPow(x, N);
      return v.toHex();
    },

    generateEphemeral: (): Ephemeral => {
      const a = SRPInt.getRandom(hashBytes);

      // A = g^a  (a = random number)
      const A = g.modPow(a, N);

      return {
        secret: a.toHex(),
        public: A.toHex(),
      };
    },

    deriveSession: async (
      clientSecretEphemeral: string,
      serverPublicEphemeral: string,
      salt: string,
      username: string,
      privateKey: string,
    ): Promise<Session> => {
      const a = SRPInt.fromHex(clientSecretEphemeral); // Secret ephemeral values
      const B = SRPInt.fromHex(serverPublicEphemeral); // Public ephemeral values
      const s = SRPInt.fromHex(salt); // User's salt
      const I = username.normalize("NFKC"); // Username
      const x = SRPInt.fromHex(privateKey); // Private key (derived from p and s)

      // A = g^a  (a = random number)
      const A = g.modPow(a, N);

      // B % N > 0
      if (B.mod(N).equals(SRPInt.ZERO)) {
        throw new SRPError("server", "InvalidPublicEphemeral");
      }

      // u = H(PAD(A), PAD(B))
      const u = await H(PAD(A), PAD(B));

      // S = (B - kg^x) ^ (a + ux)
      const S = B.subtract((await k()).multiply(g.modPow(x, N))).modPow(
        a.add(u.multiply(x)),
        N,
      );

      // K = H(S)
      // M = H(H(N) xor H(g), H(I), s, A, B, K)
      const [K, HN, Hg, HI] = await Promise.all([H(S), H(N), H(g), H(I)]);
      const M = await H(HN.xor(Hg), HI, s, A, B, K);

      return {
        key: K.toHex(),
        proof: M.toHex(),
      };
    },

    verifySession: async (
      clientPublicEphemeral: string,
      clientSession: Session,
      serverSessionProof: string,
    ): Promise<void> => {
      const A = SRPInt.fromHex(clientPublicEphemeral); // Public ephemeral values
      const M = SRPInt.fromHex(clientSession.proof); // Proof of K
      const K = SRPInt.fromHex(clientSession.key); // Shared, strong session key

      // H(A, M, K)
      const expected = await H(A, M, K);
      const actual = SRPInt.fromHex(serverSessionProof);

      if (!actual.equals(expected)) {
        throw new SRPError("server", "InvalidSessionProof");
      }
    },
  };
};
