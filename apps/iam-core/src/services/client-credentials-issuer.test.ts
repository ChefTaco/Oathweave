import { afterAll, expect, it, vi } from 'vitest'
import { generateKeyPair, exportJWK, decodeJwt, SignJWT } from 'jose'
// Machine policies are read when the token service loads, so they are set before it is imported.
const mocks = vi.hoisted(() => {
  process.env['IAM_MACHINE_CLIENT_POLICIES'] = JSON.stringify({
    'fixture-studio': { audience: 'fixture-resource', permissions: ['fixture-resource:act'], rotationOwner: 'fixture-owner', issuer: 'browser' },
    'fixture-native': { audience: 'fixture-api', permissions: ['fixture-api:read'], rotationOwner: 'fixture-owner' },
  })
  process.env['IAM_BROWSER_ISSUER'] = 'https://identity.example.com'
  return { keys: {} as { privateKey?: CryptoKey; jwks?: unknown } }
})
vi.mock('../db/client.js', () => ({ prisma: { session: { findFirst: vi.fn() } } }))
vi.mock('../config/env.js', () => ({ env: { JWT_ISSUER: 'native-identity', JWT_ACCESS_TTL: 3600 } }))
vi.mock('../utils/keys.js', () => ({ getPrivateKey: async () => mocks.keys.privateKey, getSigningKeyId: async () => 'fixture-signing', getPublishedSigningJwks: async () => mocks.keys.jwks }))
const { issueClientCredentialsToken, issuerForClientCredentials, verifyAccessToken } = await import('./token-service.js')
const pair = await generateKeyPair('RS256')
mocks.keys.privateKey = pair.privateKey
mocks.keys.jwks = { keys: [{ ...await exportJWK(pair.publicKey), kid: 'fixture-signing' }] }
afterAll(() => {
  delete process.env['IAM_MACHINE_CLIENT_POLICIES']
  delete process.env['IAM_BROWSER_ISSUER']
})

it('keeps client_credentials tokens on the native issuer unless the machine policy selects the browser issuer', async () => {
  expect(issuerForClientCredentials('fixture-native')).toBe('native-identity')
  expect(issuerForClientCredentials('fixture-studio')).toBe('https://identity.example.com')
  expect(issuerForClientCredentials('unlisted-client')).toBe('native-identity')

  const studio = await issueClientCredentialsToken('fixture-studio', 'Fixture studio', 'fixture-resource:act fixture-api:read')
  expect(decodeJwt(studio)).toMatchObject({ iss: 'https://identity.example.com', aud: 'fixture-resource', sub: 'fixture-studio', clientId: 'fixture-studio', actorType: 'SERVICE_ACCOUNT', permissions: ['fixture-resource:act'] })
  expect(await verifyAccessToken(studio)).toMatchObject({ clientId: 'fixture-studio', actorType: 'SERVICE_ACCOUNT' })

  const native = await issueClientCredentialsToken('fixture-native', 'Fixture native', 'fixture-api:read')
  expect(decodeJwt(native)).toMatchObject({ iss: 'native-identity', aud: 'fixture-api' })
  expect(await verifyAccessToken(native)).toMatchObject({ clientId: 'fixture-native' })
})

it('refuses a client_credentials token whose issuer is not the one its policy selects', async () => {
  const now = Math.floor(Date.now() / 1000)
  const forged = (clientId: string, issuer: string) => new SignJWT({ actorType: 'SERVICE_ACCOUNT', clientId, token_type: 'access', roles: [], permissions: [] })
    .setProtectedHeader({ alg: 'RS256', kid: 'fixture-signing' }).setSubject(clientId).setIssuer(issuer).setIssuedAt(now).setExpirationTime(now + 300).setJti('fixture-token').sign(pair.privateKey)
  await expect(verifyAccessToken(await forged('fixture-studio', 'native-identity'))).rejects.toThrow(/issuer/)
  await expect(verifyAccessToken(await forged('fixture-native', 'https://identity.example.com'))).rejects.toThrow(/issuer/)
})
