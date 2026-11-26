/**
 * Introspection, revocation, session sign-out and token-endpoint allowlists against the real
 * routes and a migrated SQLite database.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)
vi.mock('../services/webauthn-service.js', () => ({
  getRegistrationOptions: async () => ({ challenge: 'fixture' }),
  verifyRegistration: async () => ({
    verified: true,
    registrationInfo: {
      credential: { id: 'fixture-credential-id', publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: ['internal'] },
      credentialDeviceType: 'multiDevice',
      credentialBackedUp: true,
    },
  }),
  getAuthenticationOptions: async () => ({}),
  verifyAuthentication: async () => ({ verified: false }),
}))

const { startRealApp } = await import('../test-support/real-app.js')
const { auditEvents } = await import('../test-support/fake-redis.js')
const harness = await startRealApp({
  IAM_MACHINE_CLIENT_POLICIES: JSON.stringify({
    'reader-service': { audience: 'reader-api', permissions: ['reader:read'], rotationOwner: 'fixture' },
    'audit-gateway': { audience: 'gateway-api', permissions: ['iam:tokens:introspect', 'iam:tokens:revoke'], rotationOwner: 'fixture' },
  }),
})

const form = (values: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(values).toString(),
})
const asClient = (id: string, secret: string, body: unknown, path: string) =>
  harness.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-client-id': id, 'x-client-secret': secret },
    body: JSON.stringify(body),
  })
const clientToken = async (id: string, secret: string, scope: string) => {
  const response = await harness.request('/api/v1/oauth/token', form({ grant_type: 'client_credentials', client_id: id, client_secret: secret, scope }))
  expect(response.status).toBe(200)
  return ((await response.json()) as { access_token: string }).access_token
}

const SECRET = 'fixture-secret-'.padEnd(40, 'x')
let alice: { accessToken: string; refreshToken: string; sessionId: string }

beforeAll(async () => {
  await harness.createClient({ id: 'reader-service', secret: SECRET, grantTypes: ['client_credentials'] })
  await harness.createClient({ id: 'other-service', secret: SECRET, grantTypes: ['client_credentials'] })
  await harness.createClient({ id: 'audit-gateway', secret: SECRET, grantTypes: ['client_credentials'] })
  await harness.createUser({ username: 'alice', password: 'alice-fixture-password', roles: [{ name: 'viewer', permissions: ['iam:users:read'] }] })
  alice = await harness.login('alice', 'alice-fixture-password')
})

describe('token introspection (RFC 7662)', () => {
  it('shows a client its own token with the standard members', async () => {
    const token = await clientToken('reader-service', SECRET, 'reader:read')
    const response = await asClient('reader-service', SECRET, { token }, '/api/v1/tokens/introspect')
    expect(response.headers.get('cache-control')).toBe('no-store')
    const body = await response.json()
    expect(body).toMatchObject({
      active: true,
      sub: 'reader-service',
      client_id: 'reader-service',
      token_type: 'Bearer',
      scope: 'reader:read',
      iss: 'https://identity.example.com',
      aud: 'reader-api',
      permissions: ['reader:read'],
    })
    expect(typeof body.exp).toBe('number')
    expect(typeof body.iat).toBe('number')
  })

  it("answers inactive for another client's or a user's token", async () => {
    const token = await clientToken('reader-service', SECRET, 'reader:read')
    expect(await (await asClient('other-service', SECRET, { token }, '/api/v1/tokens/introspect')).json()).toEqual({ active: false })
    expect(await (await asClient('other-service', SECRET, { token: alice.accessToken }, '/api/v1/tokens/introspect')).json()).toEqual({ active: false })
  })

  it('shows any token to a client granted iam:tokens:introspect', async () => {
    const body = await (await asClient('audit-gateway', SECRET, { token: alice.accessToken }, '/api/v1/tokens/introspect')).json()
    expect(body).toMatchObject({ active: true, username: 'alice', session_id: alice.sessionId, actor_type: 'USER' })
    expect(body.scope).toBeUndefined()
  })
})

describe('token revocation (RFC 7009)', () => {
  it("refuses another client's token and leaves its session alone", async () => {
    const response = await asClient('other-service', SECRET, { token: alice.accessToken }, '/api/v1/tokens/revoke')
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'unauthorized_client' })
    const me = await harness.request('/api/v1/auth/me', { headers: { authorization: `Bearer ${alice.accessToken}` } })
    expect(me.status).toBe(200)
    expect(auditEvents.some((event) => event.eventType === 'token.revoke_denied')).toBe(true)
  })

  it("refuses another client's refresh token, and answers 200 for an unknown token", async () => {
    expect((await asClient('other-service', SECRET, { token: alice.refreshToken, token_type_hint: 'refresh_token' }, '/api/v1/tokens/revoke')).status).toBe(400)
    expect((await asClient('other-service', SECRET, { token: 'obviously-not-a-token' }, '/api/v1/tokens/revoke')).status).toBe(200)
    const stored = await harness.prisma.refreshToken.findFirst({ where: { sessionId: alice.sessionId } })
    expect(stored?.revokedAt).toBeNull()
  })

  it('lets a client granted iam:tokens:revoke end the session', async () => {
    const bob = await harness.createUser({ username: 'bob', password: 'bob-fixture-password' })
    const tokens = await harness.login('bob', 'bob-fixture-password')
    expect((await asClient('audit-gateway', SECRET, { token: tokens.accessToken }, '/api/v1/tokens/revoke')).status).toBe(200)
    const session = await harness.prisma.session.findUnique({ where: { id: tokens.sessionId } })
    expect(session?.revokedAt).not.toBeNull()
    expect(session?.userId).toBe(bob.id)
  })
})

describe('signing other people out', () => {
  it('needs standing over the account, as other user management does', async () => {
    await harness.createUser({ username: 'root', password: 'root-fixture-password', roles: [{ name: 'SUPER_ADMIN', permissions: ['iam:sessions:revoke', 'iam:users:write'] }] })
    const root = await harness.login('root', 'root-fixture-password')
    const helper = await harness.createUser({ username: 'helpdesk', password: 'helpdesk-fixture-password', roles: [{ name: 'helpdesk', permissions: ['iam:sessions:revoke', 'iam:users:read'] }] })
    const desk = await harness.login('helpdesk', 'helpdesk-fixture-password')
    const asDesk = { method: 'DELETE', headers: { authorization: `Bearer ${desk.accessToken}` } }

    expect((await harness.request(`/api/v1/sessions/${root.sessionId}`, asDesk)).status).toBe(403)
    const rootUser = await harness.prisma.session.findUnique({ where: { id: root.sessionId } })
    expect((await harness.request(`/api/v1/sessions/user/${rootUser!.userId}`, asDesk)).status).toBe(403)
    expect((await harness.prisma.session.findUnique({ where: { id: root.sessionId } }))?.revokedAt).toBeNull()

    // Alice holds nothing the help desk lacks, so it may sign her out; and anyone may sign themselves out.
    const aliceSession = await harness.login('alice', 'alice-fixture-password')
    expect((await harness.request(`/api/v1/sessions/${aliceSession.sessionId}`, asDesk)).status).toBe(200)
    expect((await harness.request(`/api/v1/sessions/user/${helper.id}`, asDesk)).status).toBe(200)
    expect((await harness.request('/api/v1/sessions/not-a-session', { method: 'DELETE', headers: { authorization: `Bearer ${root.accessToken}` } })).status).toBe(404)
  })
})

describe('client address allowlists', () => {
  it('apply at the token endpoint, with CIDR ranges', async () => {
    await harness.createClient({ id: 'ranged-out', secret: SECRET, grantTypes: ['client_credentials'], allowedIps: ['10.0.0.0/8', '2001:db8::/32'] })
    await harness.createClient({ id: 'ranged-in', secret: SECRET, grantTypes: ['client_credentials'], allowedIps: ['198.51.100.0/24'] })
    const refused = await harness.request('/api/v1/oauth/token', form({ grant_type: 'client_credentials', client_id: 'ranged-out', client_secret: SECRET }))
    expect(refused.status).toBe(401)
    expect(await refused.json()).toMatchObject({ error: 'invalid_client' })
    expect((await harness.request('/api/v1/oauth/token', form({ grant_type: 'client_credentials', client_id: 'ranged-in', client_secret: SECRET }))).status).toBe(200)
  })
})

describe('the first passkey', () => {
  it('turns MFA on with recovery codes and an audit record', async () => {
    const carol = await harness.createUser({ username: 'carol', password: 'carol-fixture-password' })
    const tokens = await harness.login('carol', 'carol-fixture-password')
    const response = await harness.request('/api/v1/mfa/webauthn/register', {
      method: 'POST',
      headers: { authorization: `Bearer ${tokens.accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ response: { id: 'fixture-credential-id' }, friendlyName: 'Laptop' }),
    })
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    const body = await response.json()
    expect(body.backupCodes).toHaveLength(10)
    const user = await harness.prisma.user.findUnique({ where: { id: carol.id } })
    expect(user?.mfaEnabled).toBe(true)
    expect((JSON.parse(user!.mfaBackupCodes!) as string[]).filter(Boolean)).toHaveLength(10)
    expect(auditEvents.filter((event) => event.actorId === carol.id).map((event) => event.eventType)).toEqual(
      expect.arrayContaining(['auth.webauthn_registered', 'auth.mfa_enabled']),
    )
  })
})
