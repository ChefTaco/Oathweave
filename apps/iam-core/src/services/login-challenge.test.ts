import { beforeEach, expect, it, vi } from 'vitest'
import { generateKeyPair, SignJWT } from 'jose'
const state = vi.hoisted(() => ({
  find: vi.fn(),
  set: vi.fn(),
  key: undefined as unknown,
}))
vi.mock('../db/client.js', () => ({
  prisma: { user: { findUnique: state.find } },
}))
vi.mock('../config/env.js', () => ({
  env: { JWT_ISSUER: 'https://identity.example.com', REDIS_PREFIX: 'fixture' },
}))
vi.mock('../utils/keys.js', () => ({ getPublicKey: async () => state.key }))
vi.mock('../queue/audit-queue.js', () => ({
  redisConnection: { set: state.set },
}))
const { loginChallengeUser, consumeLoginChallenge } = await import(
  './login-challenge.js'
)
const keys = await generateKeyPair('RS256')
state.key = keys.publicKey
const token = (version = 123, purpose = 'mfa_challenge') =>
  new SignJWT({ purpose, passwordVersion: version })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject('fake-user')
    .setJti('fake-challenge')
    .setIssuer('https://identity.example.com')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(keys.privateKey)
beforeEach(() => {
  state.find.mockResolvedValue({
    active: true,
    mfaEnabled: true,
    lockedUntil: null,
    passwordChangedAt: new Date(123),
  })
  state.set.mockResolvedValue('OK')
})
it('rejects a challenge after password replacement, account disablement or purpose substitution', async () => {
  expect(await loginChallengeUser(await token())).toBe('fake-user')
  await expect(loginChallengeUser(await token(122))).rejects.toThrow(
    'identity changed',
  )
  await expect(
    loginChallengeUser(await token(123, 'password_reset')),
  ).rejects.toThrow()
  state.find.mockResolvedValue({
    active: false,
    mfaEnabled: true,
    passwordChangedAt: new Date(123),
  })
  await expect(loginChallengeUser(await token())).rejects.toThrow()
})
it('a second-factor challenge can be consumed only once across authentication methods', async () => {
  const value = await token()
  await expect(consumeLoginChallenge(value)).resolves.toBeUndefined()
  state.set.mockResolvedValue(null)
  await expect(consumeLoginChallenge(value)).rejects.toThrow(
    'already been used',
  )
  expect(state.set.mock.calls[0]?.[0]).not.toContain(value)
  expect(state.set.mock.calls[0]?.slice(2)).toEqual(['EX', 300, 'NX'])
})
