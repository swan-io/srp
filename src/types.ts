export type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
export type PrimeGroup = 1024 | 1536 | 2048 | 3072 | 4096 | 6144 | 8192;

export type Entity = "Client" | "Server";
export type ErrorCode = "InvalidPublicEphemeral" | "InvalidSessionProof";

export type Ephemeral = {
  public: string;
  secret: string;
};

export type Session = {
  key: string;
  proof: string;
};
