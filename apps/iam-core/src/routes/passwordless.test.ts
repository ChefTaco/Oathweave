/** Passwordless sign-in with a discoverable passkey, verified end to end by the real server. */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const { startRealApp } = await import('../test-support/real-app.js')
const { softPasskey } = await import('../test-support/soft-authenticator.js')
const { auditEvents, resetFakeRedis } = await import('../test-support/fake-redis.js')
const RP = { rpId: 'identity.example.com', origin: 'https://identity.example.com' }
const harness = await startRealApp({ WEBAUTHN_RP_ID: RP.rpId, WEBAUTHN_RP_ORIGIN: RP.origin })

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  harness.request(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) })
const passkey = softPasskey()
let userId: string

async function options(): Promise<{ ceremonyId: string; challenge: string }> {
  const response = await post('/api/v1/mfa/webauthn/passwordless/options', {})
  expect(response.status).toBe(200)
  const body = (await response.json()) as { ceremonyId: string; data: { challenge: string; allowCredentials?: unknown[]; userVerification: string } }
  expect(body.data.allowCredentials ?? []).toEqual([])
  expect(body.data.userVerification).toBe('required')
  return { ceremonyId: body.ceremonyId, challenge: body.data.challenge }
}

beforeAll(async () => {
  userId = (await harness.createUser({ username: 'ivan', password: 'ivan-fixture-password', roles: [{ name: 'viewer', permissions: ['iam:users:read'] }] })).id
  await harness.prisma.webAuthnCredential.create({
    data: { id: 'fixture-passkey', userId, credentialId: passkey.credentialId, publicKey: passkey.publicKey, counter: 0, deviceType: 'multiDevice', backedUp: true, transports: '["internal"]', friendlyName: 'Phone' },
  })
  await harness.prisma.user.update({ where: { id: userId }, data: { mfaEnabled: true } })
})

// Each case starts with fresh sign-in throttles (and no leftover ceremonies).
beforeEach(() => resetFakeRedis())

describe('passwordless passkey sign-in', () => {
  it('signs the passkey owner in with no password', async () => {
    const { ceremonyId, challenge } = await options()
    const response = await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId, response: passkey.assert({ ...RP, challenge, counter: 1 }) })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { accessToken: string; user: { id: string; roles: string[] } }
    expect(body.user).toMatchObject({ id: userId, roles: ['viewer'] })
    expect((await harness.request('/api/v1/auth/me', { headers: { authorization: `Bearer ${body.accessToken}` } })).status).toBe(200)
    expect((await harness.prisma.webAuthnCredential.findUnique({ where: { id: 'fixture-passkey' } }))?.counter).toBe(1)
    expect(auditEvents.some((event) => event.eventType === 'auth.passkey_sign_in' && event.actorId === userId)).toBe(true)
  })

  it('refuses a replayed ceremony, a ceremony bound to another sign-in, and no user verification', async () => {
    const first = await options()
    const assertion = passkey.assert({ ...RP, challenge: first.challenge, counter: 2 })
    expect((await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId: first.ceremonyId, response: assertion })).status).toBe(200)
    expect((await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId: first.ceremonyId, response: assertion })).status).toBe(401)

    const a = await options()
    const b = await options()
    expect((await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId: b.ceremonyId, response: passkey.assert({ ...RP, challenge: a.challenge, counter: 3 }) })).status).toBe(401)
    const c = await options()
    expect((await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId: c.ceremonyId, response: passkey.assert({ ...RP, challenge: c.challenge, counter: 4, userVerified: false }) })).status).toBe(401)
  })

  it('refuses an unknown passkey and a disabled account', async () => {
    const stranger = softPasskey()
    const one = await options()
    expect((await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId: one.ceremonyId, response: stranger.assert({ ...RP, challenge: one.challenge, counter: 1 }) })).status).toBe(401)
    await harness.prisma.user.update({ where: { id: userId }, data: { active: false } })
    try {
      const two = await options()
      expect((await post('/api/v1/mfa/webauthn/passwordless/authenticate', { ceremonyId: two.ceremonyId, response: passkey.assert({ ...RP, challenge: two.challenge, counter: 9 }) })).status).toBe(401)
    } finally {
      await harness.prisma.user.update({ where: { id: userId }, data: { active: true } })
    }
  })

  it('sets the browser SSO cookie for a browser sign-in, not tokens in the body', async () => {
    const { ceremonyId, challenge } = await options()
    const response = await post(
      '/api/v1/mfa/webauthn/passwordless/authenticate',
      { ceremonyId, response: passkey.assert({ ...RP, challenge, counter: 20 }) },
      { origin: 'https://console.example.com', 'x-oathweave-browser': 'true' },
    )
    expect(response.status).toBe(200)
    expect(response.headers.get('set-cookie')).toContain('__Host-oathweave_sso=')
    const body = await response.json()
    expect(body.accessToken).toBeUndefined()
    expect(body.refreshToken).toBeUndefined()
  })
})

describe('IAM_PASSWORDLESS_PASSKEYS', () => {
  it('defaults on and accepts only exact booleans', async () => {
    const { envSchema } = await import('../config/env-schema.js')
    const base = { DATABASE_URL: 'file:/tmp/x.db', JWT_PRIVATE_KEY_PATH: '/tmp/a', JWT_PUBLIC_KEY_PATH: '/tmp/b', COOKIE_SECRET: 'x'.repeat(32), IAM_AGENT_SECRET: 'x'.repeat(16) }
    expect(envSchema.parse(base).IAM_PASSWORDLESS_PASSKEYS).toBe(true)
    expect(envSchema.parse({ ...base, IAM_PASSWORDLESS_PASSKEYS: 'false' }).IAM_PASSWORDLESS_PASSKEYS).toBe(false)
    expect(envSchema.safeParse({ ...base, IAM_PASSWORDLESS_PASSKEYS: 'yes' }).success).toBe(false)
  })
})
