import { createSRPClient, createSRPServer } from "../src";

test("LinusU/secure-remote-password test", async () => {
  const client = createSRPClient("SHA-256", 2048);
  const server = createSRPServer("SHA-256", 2048);

  const username = "linus@folkdatorn.se";
  const password = "$uper$ecure";

  const salt = client.generateSalt();
  const privateKey = await client.derivePrivateKey(salt, username, password);
  const verifier = client.deriveVerifier(privateKey);

  const clientEphemeral = client.generateEphemeral();
  const serverEphemeral = await server.generateEphemeral(verifier);

  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  );

  const serverSession = await server.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    username,
    verifier,
    clientSession.proof,
  );

  await client.verifySession(
    clientEphemeral.public,
    clientSession,
    serverSession.proof,
  );

  expect(clientSession.key).toStrictEqual(serverSession.key);
});
