# @swan-io/srp

A modern [SRP](http://srp.stanford.edu) implementation for Node.js (v15+) and web browsers. Living fork of [secure-remote-password](https://github.com/LinusU/secure-remote-password).

## Installation

```sh
yarn add @swan-io/srp
```

## Usage

### Signing up

When creating an account with the server, the client will provide a salt and a verifier for the server to store. They are calculated by the client as follows:

```ts
import { createSRPClient } from "@swan-io/srp";
const client = createSRPClient("SHA-256", 2048);

// These should come from the user signing up
const username = "linus@folkdatorn.se";
const password = "$uper$ecure";

const salt = client.generateSalt();
const privateKey = await client.deriveSafePrivateKey(salt, password);
const verifier = client.deriveVerifier(privateKey);

// Send `username`, `salt` and `verifier` to the server
```

⚠️  Note that `derivePrivateKey` is also provided for completeness with the SRP-6a specification. It is, however, recommended to avoid using it as it's highly exposed to brute force attack against the verifier. Also, the use of a `username` as part of the verifier calculation means that if it changes, the salt and verifier needs to be updated to.

To avoid these issues, we provide a `deriveSafePrivateKey` function that uses [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) for "slow hashing".<br>
When using it instead of `derivePrivateKey`, as the private key is not generated using an `username`, you will have to pass an empty string to the `deriveSession` function instead (`""`). The downside of this method is that a server can do an attack to determine whether two users have the same password. This is an acceptable trade-off.

### Logging in

Authenticating with the server involves multiple steps.

**1** - The client generates a secret/public ephemeral value pair.

```ts
import { createSRPClient } from "@swan-io/srp";
const client = createSRPClient("SHA-256", 2048);

// This should come from the user logging in
const username = "linus@folkdatorn.se";
const clientEphemeral = client.generateEphemeral();

// Send `username` and `clientEphemeral.public` to the server
```

**2** - The server receives the client's public ephemeral value and username. Using the username we retrieve the `salt` and `verifier` from our user database. We then generate our own ephemeral value pair.

_note:_ if no user cannot be found in the database, a bogus salt and ephemeral value should be returned, to avoid leaking which users have signed up.

```ts
import { createSRPServer } from "@swan-io/srp";
const server = createSRPServer("SHA-256", 2048);

// This should come from the user database
const salt = "fb95867e…";
const verifier = "9392093f…";

const serverEphemeral = await server.generateEphemeral(verifier);

// Store `serverEphemeral.secret` for later use
// Send `salt` and `serverEphemeral.public` to the client
```

**3** - The client can now derive the shared strong session key and a proof of it to provide to the server.

```ts
import { createSRPClient } from "@swan-io/srp";
const client = createSRPClient("SHA-256", 2048);

// This should come from the user logging in
const password = "$uper$ecret";
const privateKey = await client.deriveSafePrivateKey(salt, password);

const clientSession = await client.deriveSession(
  clientEphemeral.secret,
  serverPublicEphemeral,
  salt,
  "", // or `username` if you used `derivePrivateKey`
  privateKey,
);

// Send `clientSession.proof` to the server
```

**4** - The server is also ready to derive the shared strong session key and can verify that the client has the same key using the provided proof.

```ts
import { createSRPServer } from "@swan-io/srp";
const server = createSRPServer("SHA-256", 2048);

// Previously stored `serverEphemeral.secret`
const serverSecretEphemeral = "784d6e83…";

const serverSession = await server.deriveSession(
  serverSecretEphemeral,
  clientPublicEphemeral,
  salt,
  "", // or `username` if you used `derivePrivateKey`
  verifier,
  clientSessionProof,
);

// Send `serverSession.proof` to the client
```

**5** - Finally, the client can verify that the server has derived the correct strong session key, using the proof that the server sent back.

```ts
import { createSRPClient } from "@swan-io/srp";
const client = createSRPClient("SHA-256", 2048);

await client.verifySession(
  clientEphemeral.public,
  clientSession,
  serverSessionProof,
);
```

## API

### Client

```ts
import { createSRPClient } from "@swan-io/srp";

type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
type PrimeGroup = 1024 | 1536 | 2048 | 3072 | 4096 | 6144 | 8192;

const hashAlgorithm: HashAlgorithm = "SHA-256";
const primeGroup: PrimeGroup = 2048;

const client = createSRPClient(hashAlgorithm, primeGroup);
```

#### client.generateSalt

Generate a salt suitable for computing the verifier with.

```ts
type generateSalt() => string;
```

#### client.derivePrivateKey

Derives a private key suitable for computing the verifier with.

```ts
type derivePrivateKey = (
  salt: string,
  username: string,
  password: string,
) => Promise<string>;
```

#### client.deriveSafePrivateKey

Derives a private key suitable for computing the verifier with using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2). By default, it will use the iterations count [recommended by OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

```ts
type deriveSafePrivateKey = (
  salt: string,
  password: string,
  iterations?: number,
) => Promise<string>;
```

#### client.deriveVerifier

Derive a verifier to be stored for subsequent authentication attempts.

```ts
type deriveVerifier = (privateKey: string) => string;
```

#### client.generateEphemeral

Generate ephemeral values used to initiate an authentication session.

```ts
type generateEphemeral = () => {
  secret: string;
  public: string;
};
```

#### client.deriveSession

Compute a session key and proof. The proof is to be sent to the server for verification.

```ts
type deriveSession = (
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  privateKey: string,
) => Promise<{
  key: string;
  proof: string;
}>;
```

#### client.verifySession

Verifies the server provided session proof.<br />
**⚠️ Rejects a SRPError if the session proof is invalid.**

```ts
type verifySession = (
  clientPublicEphemeral: string,
  clientSession: Session,
  serverSessionProof: string,
) => Promise<void>;
```

### Server

```ts
import { createSRPServer } from "@swan-io/srp";

type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
type PrimeGroup = 1024 | 1536 | 2048 | 3072 | 4096 | 6144 | 8192;

const hashAlgorithm: HashAlgorithm = "SHA-256";
const primeGroup: PrimeGroup = 2048;

const server = createSRPServer(hashAlgorithm, primeGroup);
```

#### server.generateEphemeral

Generate ephemeral values used to continue an authentication session.

```ts
type generateEphemeral = (verifier: string) => Promise<{
  public: string;
  secret: string;
}>;
```

#### server.deriveSession

Compute a session key and proof. The proof is to be sent to the client for verification.<br />
**⚠️ Rejects a SRPError if the session proof from the client is invalid.**

```ts
type deriveSession = (
  serverSecretEphemeral: string,
  clientPublicEphemeral: string,
  salt: string,
  username: string,
  verifier: string,
  clientSessionProof: string,
) => Promise<{
  key: string;
  proof: string;
}>;
```
