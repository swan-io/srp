import { getParams } from "./params";
import { SRPInt } from "./SRPInt";
import { Ephemeral, Session } from "./types";

export const createSRPServer = (...args: Parameters<typeof getParams>) => {
  const { N, g, k, H, PAD, hashBytes } = getParams(...args);

  return {
    generateEphemeral: async (verifier: string): Promise<Ephemeral> => {
      // v      Password verifier
      const v = SRPInt.fromHex(verifier);

      // B = kv + g^b             (b = random number)
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
      // b      Secret ephemeral values
      // A      Public ephemeral values
      // s      User's salt
      // p      Cleartext Password
      // I      Username
      // v      Password verifier
      const b = SRPInt.fromHex(serverSecretEphemeral);
      const A = SRPInt.fromHex(clientPublicEphemeral);
      const s = SRPInt.fromHex(salt);
      const I = String(username);
      const v = SRPInt.fromHex(verifier);

      // B = kv + g^b             (b = random number)
      const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N);

      // A % N > 0
      if (A.mod(N).equals(SRPInt.ZERO)) {
        // fixme: .code, .statusCode, etc.
        throw new Error("The client sent an invalid public ephemeral");
      }

      // u = H(PAD(A), PAD(B))
      const u = await H(PAD(A), PAD(B));

      // S = (Av^u) ^ b              (computes session key)
      const S = A.multiply(v.modPow(u, N)).modPow(b, N);

      // K = H(S)
      const K = await H(S);

      // M = H(H(N) xor H(g), H(I), s, A, B, K)
      const M = await H((await H(N)).xor(await H(g)), await H(I), s, A, B, K);

      const expected = M;
      const actual = SRPInt.fromHex(clientSessionProof);

      if (!actual.equals(expected)) {
        // fixme: .code, .statusCode, etc.
        throw new Error("Client provided session proof is invalid");
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
