import { expect, test } from 'bun:test'
import { createSRPClient, createSRPServer, SRPError } from '../src'
import type { ErrorCode } from '../src'

const expectSRPError = async (
  run: () => Promise<unknown>,
  responsible: 'client' | 'server',
  code: ErrorCode,
): Promise<void> => {
  try {
    await run()
    throw new Error('Expected promise to reject')
  } catch (error) {
    expect(error).toBeInstanceOf(SRPError)

    if (error instanceof SRPError) {
      expect(error.responsible).toStrictEqual(responsible)
      expect(error.code).toStrictEqual(code)
    }
  }
}

const tamperHex = (hex: string): string =>
  `${hex.slice(0, -1)}${hex.endsWith('0') ? '1' : '0'}`

test('LinusU/secure-remote-password session test', async () => {
  const client = createSRPClient('SHA-256', 2048)
  const server = createSRPServer('SHA-256', 2048)

  const username = 'linus@folkdatorn.se'
  const password = '$uper$ecure'

  const salt = client.generateSalt()
  const privateKey = await client.derivePrivateKey(salt, username, password)
  const verifier = client.deriveVerifier(privateKey)
  const clientEphemeral = client.generateEphemeral()
  const serverEphemeral = await server.generateEphemeral(verifier)

  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  )

  const serverSession = await server.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    username,
    verifier,
    clientSession.proof,
  )

  await client.verifySession(
    clientEphemeral.public,
    clientSession,
    serverSession.proof,
  )

  expect(clientSession.key).toStrictEqual(serverSession.key)
})

test('PBKDF2 session test', async () => {
  const client = createSRPClient('SHA-256', 4096)
  const server = createSRPServer('SHA-256', 4096)

  const username = ''
  const password = 'password123'

  const salt = client.generateSalt()
  const privateKey = await client.deriveSafePrivateKey(salt, password)
  const verifier = client.deriveVerifier(privateKey)
  const clientEphemeral = client.generateEphemeral()
  const serverEphemeral = await server.generateEphemeral(verifier)

  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  )

  const serverSession = await server.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    username,
    verifier,
    clientSession.proof,
  )

  await client.verifySession(
    clientEphemeral.public,
    clientSession,
    serverSession.proof,
  )

  expect(clientSession.key).toStrictEqual(serverSession.key)
})

test('client should reject invalid server public ephemeral', async () => {
  const client = createSRPClient('SHA-256', 2048)

  const username = 'linus@folkdatorn.se'
  const password = '$uper$ecure'
  const salt = client.generateSalt()
  const privateKey = await client.derivePrivateKey(salt, username, password)
  const clientEphemeral = client.generateEphemeral()

  await expectSRPError(
    () =>
      client.deriveSession(
        clientEphemeral.secret,
        '0',
        salt,
        username,
        privateKey,
      ),
    'server',
    'InvalidPublicEphemeral',
  )
})

test('server should reject invalid client public ephemeral', async () => {
  const client = createSRPClient('SHA-256', 2048)
  const server = createSRPServer('SHA-256', 2048)

  const username = 'linus@folkdatorn.se'
  const password = '$uper$ecure'
  const salt = client.generateSalt()
  const privateKey = await client.derivePrivateKey(salt, username, password)
  const verifier = client.deriveVerifier(privateKey)
  const serverEphemeral = await server.generateEphemeral(verifier)

  await expectSRPError(
    () =>
      server.deriveSession(
        serverEphemeral.secret,
        '0',
        salt,
        username,
        verifier,
        '00',
      ),
    'client',
    'InvalidPublicEphemeral',
  )
})

test('server should reject invalid client session proof', async () => {
  const client = createSRPClient('SHA-256', 2048)
  const server = createSRPServer('SHA-256', 2048)

  const username = 'linus@folkdatorn.se'
  const password = '$uper$ecure'

  const salt = client.generateSalt()
  const privateKey = await client.derivePrivateKey(salt, username, password)
  const verifier = client.deriveVerifier(privateKey)
  const clientEphemeral = client.generateEphemeral()
  const serverEphemeral = await server.generateEphemeral(verifier)
  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  )

  await expectSRPError(
    () =>
      server.deriveSession(
        serverEphemeral.secret,
        clientEphemeral.public,
        salt,
        username,
        verifier,
        tamperHex(clientSession.proof),
      ),
    'client',
    'InvalidSessionProof',
  )

  await expectSRPError(
    () =>
      server.deriveSession(
        serverEphemeral.secret,
        clientEphemeral.public,
        salt,
        username,
        verifier,
        'zz',
      ),
    'client',
    'InvalidSessionProof',
  )
})

test('client should reject malformed server session proof', async () => {
  const client = createSRPClient('SHA-256', 2048)
  const server = createSRPServer('SHA-256', 2048)

  const username = 'linus@folkdatorn.se'
  const password = '$uper$ecure'

  const salt = client.generateSalt()
  const privateKey = await client.derivePrivateKey(salt, username, password)
  const verifier = client.deriveVerifier(privateKey)
  const clientEphemeral = client.generateEphemeral()
  const serverEphemeral = await server.generateEphemeral(verifier)
  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  )

  await expectSRPError(
    () => client.verifySession(clientEphemeral.public, clientSession, 'zz'),
    'server',
    'InvalidSessionProof',
  )
})
