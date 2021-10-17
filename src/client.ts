import { Params } from "./params";
import { SRPInt } from "./SRPInt";
import { Ephemeral, Session } from "./types";

export const generateSalt = (params: Params): string => {
  // s      User's salt
  const s = SRPInt.getRandom(params.hashBytes);

  return s.toHex();
};

export const derivePrivateKey = async (
  params: Params,
  salt: string,
  username: string,
  password: string,
): Promise<string> => {
  // H()    One-way hash function
  const { H } = params;

  // s      User's salt
  // I      Username
  // p      Cleartext Password
  const s = SRPInt.fromHex(salt);
  const I = String(username);
  const p = String(password);

  // x = H(s, H(I | ':' | p))  (s is chosen randomly)
  const x = await H(s, await H(`${I}:${p}`));

  return x.toHex();
};

export const deriveVerifier = (params: Params, privateKey: string): string => {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  const { N, g } = params;

  // x      Private key (derived from p and s)
  const x = SRPInt.fromHex(privateKey);

  // v = g^x                   (computes password verifier)
  const v = g.modPow(x, N);

  return v.toHex();
};

export const generateEphemeral = (params: Params): Ephemeral => {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  const { N, g } = params;

  // A = g^a                  (a = random number)
  const a = SRPInt.getRandom(params.hashBytes);
  const A = g.modPow(a, N);

  return {
    secret: a.toHex(),
    public: A.toHex(),
  };
};

export const deriveSession = async (
  params: Params,
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  privateKey: string,
): Promise<Session> => {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  // k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()    One-way hash function
  // PAD()  Pad the number to have the same number of bytes as N
  const { N, g, H, PAD } = params;
  const k = await params.k;

  // a      Secret ephemeral values
  // B      Public ephemeral values
  // s      User's salt
  // I      Username
  // x      Private key (derived from p and s)
  const a = SRPInt.fromHex(clientSecretEphemeral);
  const B = SRPInt.fromHex(serverPublicEphemeral);
  const s = SRPInt.fromHex(salt);
  const I = String(username);
  const x = SRPInt.fromHex(privateKey);

  // A = g^a                  (a = random number)
  const A = g.modPow(a, N);

  // B % N > 0
  if (B.mod(N).equals(SRPInt.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The server sent an invalid public ephemeral");
  }

  // u = H(PAD(A), PAD(B))
  const u = await H(PAD(A), PAD(B));

  // S = (B - kg^x) ^ (a + ux)
  const S = B.subtract(k.multiply(g.modPow(x, N))).modPow(
    a.add(u.multiply(x)),
    N,
  );

  // K = H(S)
  const K = await H(S);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H((await H(N)).xor(await H(g)), await H(I), s, A, B, K);

  return {
    key: K.toHex(),
    proof: M.toHex(),
  };
};

export const verifySession = async (
  params: Params,
  clientPublicEphemeral: string,
  clientSession: Session,
  serverSessionProof: string,
): Promise<void> => {
  // H()    One-way hash function
  const { H } = params;

  // A      Public ephemeral values
  // M      Proof of K
  // K      Shared, strong session key
  const A = SRPInt.fromHex(clientPublicEphemeral);
  const M = SRPInt.fromHex(clientSession.proof);
  const K = SRPInt.fromHex(clientSession.key);

  // H(A, M, K)
  const expected = await H(A, M, K);
  const actual = SRPInt.fromHex(serverSessionProof);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Server provided session proof is invalid");
  }
};
