import { SRPError } from "./errors";
import { getParams } from "./params";
import { SRPInt } from "./SRPInt";
import { Ephemeral, Session } from "./types";

export const createSRPServer = (...args: Parameters<typeof getParams>) => {
  const { N, g, k, H, PAD, hashBytes } = getParams(...args);

  return {
    generateEphemeral: async (verifier: string): Promise<Ephemeral> => {
      const v = SRPInt.fromHex(verifier); // Password verifier

      // B = kv + g^b  (b = random number)
      const b = SRPInt.getRandom(hashBytes);
      const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N);

      return {
        secret: b.toHex(),
        public: B.toHex(),
      };
    },

    deriveSession: async (
      serverSecretEphemeral: string,
      clientPublicEphemeral: string,
      salt: string,
      username: string,
      verifier: string,
      clientSessionProof: string,
    ): Promise<Session> => {
      const b = SRPInt.fromHex(serverSecretEphemeral); // Secret ephemeral values
      const A = SRPInt.fromHex(clientPublicEphemeral); // Public ephemeral values
      const s = SRPInt.fromHex(salt); // User's salt
      const I = String(username); // Username
      const v = SRPInt.fromHex(verifier); // Password verifier

      // B = kv + g^b  (b = random number)
      const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N);

      // A % N > 0
      if (A.mod(N).equals(SRPInt.ZERO)) {
        throw new SRPError("client", "invalidPublicEphemeral");
      }

      // u = H(PAD(A), PAD(B))
      const u = await H(PAD(A), PAD(B));

      // S = (Av^u) ^ b  (computes session key)
      const S = A.multiply(v.modPow(u, N)).modPow(b, N);

      // K = H(S)
      // M = H(H(N) xor H(g), H(I), s, A, B, K)
      const [K, HN, Hg, HI] = await Promise.all([H(S), H(N), H(g), H(I)]);
      const M = await H(HN.xor(Hg), HI, s, A, B, K);

      const expected = M;
      const actual = SRPInt.fromHex(clientSessionProof);

      if (!actual.equals(expected)) {
        throw new SRPError("client", "invalidSessionProof");
      }

      // P = H(A, M, K)
      const P = await H(A, M, K);

      return {
        key: K.toHex(),
        proof: P.toHex(),
      };
    },
  };
};
