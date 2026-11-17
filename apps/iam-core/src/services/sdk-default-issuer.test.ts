import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, expect, it, vi } from 'vitest'
import { exportSPKI, generateKeyPair, SignJWT } from 'jose'
import { DEFAULT_IAM_ISSUER, IamVerifier } from '../../../../packages/iam-sdk/src/index.js'

// The server is configured the way the CLI and container image leave it when JWT_ISSUER is unset.
const mocks = vi.hoisted(() => ({ keys: {} as { privateKey?: CryptoKey } }))
vi.mock('../config/env.js', async () => {
  const { applyCliDefaults } = await import('../cli/defaults.js')
  const source: Record<string, string | undefined> = { HIVE_HOME: '/nonexistent/fixture-home' }
  applyCliDefaults(source)
  return { env: { JWT_ISSUER: source['JWT_ISSUER'], JWT_ACCESS_TTL: 900 } }
})
vi.mock('../db/client.js', () => ({ prisma: {} }))
vi.mock('../utils/keys.js', () => ({ getPrivateKey: async () => mocks.keys.privateKey, getSigningKeyId: async () => 'fixture-signing', getPublishedSigningJwks: async () => ({ keys: [] }) }))
const { issueServiceAccountToken } = await import('./token-service.js')
const { env } = await import('../config/env.js')

let server: Server
let publicKeyUrl: string

beforeAll(async () => {
  const pair = await generateKeyPair('RS256')
  mocks.keys.privateKey = pair.privateKey
  const pem = await exportSPKI(pair.publicKey)
  server = createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }).end(pem) })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  publicKeyUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1/auth/public-key`
})
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())))

it('accepts a default-configured server token with an SDK verifier that sets no issuer', async () => {
  expect(env.JWT_ISSUER).toBe(DEFAULT_IAM_ISSUER)
  const token = await issueServiceAccountToken('fixture-service', 'fixture-client', [], ['fixture:read'])
  await expect(new IamVerifier({ publicKeyUrl }).verify(token)).resolves.toMatchObject({
    sub: 'fixture-service', actorType: 'SERVICE_ACCOUNT', clientId: 'fixture-client', permissions: ['fixture:read'],
  })
})

it('keeps an explicit SDK issuer in charge of the default', async () => {
  const token = await issueServiceAccountToken('fixture-service', 'fixture-client', [], [])
  await expect(new IamVerifier({ publicKeyUrl, issuer: 'https://identity.example.com' }).verify(token))
    .rejects.toThrow('IAM token verification failed')
  const now = Math.floor(Date.now() / 1000)
  const configured = await new SignJWT({ actorType: 'SERVICE_ACCOUNT', clientId: 'fixture-client', roles: [], permissions: [] })
    .setProtectedHeader({ alg: 'RS256', kid: 'fixture-signing' }).setSubject('fixture-service').setIssuer('https://identity.example.com')
    .setIssuedAt(now).setExpirationTime(now + 60).setJti('fixture-explicit').sign(mocks.keys.privateKey!)
  await expect(new IamVerifier({ publicKeyUrl, issuer: 'https://identity.example.com' }).verify(configured))
    .resolves.toMatchObject({ sub: 'fixture-service' })
  await expect(new IamVerifier({ publicKeyUrl }).verify(configured)).rejects.toThrow('IAM token verification failed')
})
