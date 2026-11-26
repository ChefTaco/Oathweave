import { beforeEach, expect, it, vi } from 'vitest'
import { decodeJwt, exportJWK, generateKeyPair } from 'jose'

const state = vi.hoisted(() => ({
  stored: null as null | {
    tokenHash: string
    userId: string
    sessionId: string | null
    clientId: string | null
    revokedAt: Date | null
    expiresAt: Date
  },
  session: null as null | { userId: string; revokedAt: Date | null; expiresAt: Date },
  client: null as null | { active: boolean; clientType: string; grantTypes: string },
  groupRoles: [] as { name: string; permissions: string }[],
  created: [] as { clientId: string | null; sessionId: string; expiresAt?: Date }[],
  revokedSessions: [] as string[],
  audits: [] as string[],
  keys: {} as { privateKey?: unknown; jwks?: { keys: Record<string, unknown>[] } },
}))
vi.mock('../config/env.js', () => ({
  env: {
    JWT_ISSUER: 'https://identity.example.com',
    JWT_ACCESS_TTL: 900,
    JWT_REFRESH_TTL: 3600,
  },
}))
vi.stubEnv(
  'IAM_BROWSER_CLIENT_POLICIES',
  JSON.stringify({
    'hivexui-example': { audience: 'example', permissions: ['example:read'] },
  }),
)
vi.stubEnv(
  'IAM_MACHINE_CLIENT_POLICIES',
  JSON.stringify({
    'example-worker': {
      audience: 'example-api',
      permissions: ['example:write'],
      rotationOwner: 'fixture',
    },
  }),
)
// The retry window's store: in memory, empty unless a rotation in the test filled it.
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)
vi.mock('../utils/keys.js', () => ({
  getPrivateKey: async () => state.keys.privateKey,
  getSigningKeyId: async () => 'fixture-kid',
  getPublishedSigningJwks: async () => state.keys.jwks,
}))
vi.mock('./session-service.js', () => ({
  createSession: vi.fn(async () => ({ sessionId: 'fresh-session' })),
  revokeSession: vi.fn(async (id: string) => {
    state.revokedSessions.push(id)
    if (state.session) state.session.revokedAt = new Date()
    return true
  }),
}))
vi.mock('./audit-service.js', () => ({
  logAuditEvent: vi.fn(async (event: { eventType: string }) => void state.audits.push(event.eventType)),
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    refreshToken: {
      updateMany: vi.fn(async () => {
        const row = state.stored
        if (!row || row.revokedAt || row.expiresAt <= new Date()) return { count: 0 }
        row.revokedAt = new Date()
        return { count: 1 }
      }),
      findUnique: vi.fn(async () => (state.stored ? { ...state.stored } : null)),
      create: vi.fn(
        async ({ data }: { data: { clientId: string | null; sessionId: string; expiresAt: Date } }) => {
          state.created.push({ clientId: data.clientId, sessionId: data.sessionId, expiresAt: data.expiresAt })
          return data
        },
      ),
    },
    session: {
      findUnique: vi.fn(async () => state.session),
      findFirst: vi.fn(async () => (state.session && !state.session.revokedAt ? { id: 'fixture-session' } : null)),
    },
    client: { findUnique: vi.fn(async () => state.client) },
    user: {
      findUnique: vi.fn(async () => ({
        id: 'fixture-user',
        email: 'person@example.com',
        username: 'person',
        active: true,
      })),
    },
    userRoleAssignment: {
      findMany: vi.fn(async () => [
        { role: { name: 'EXAMPLE', permissions: JSON.stringify(['example:read', 'example:write']) } },
      ]),
    },
    groupMember: {
      findMany: vi.fn(async () =>
        state.groupRoles.length ? [{ group: { roles: state.groupRoles.map((role) => ({ role })) } }] : []),
    },
  },
}))

const { rotateRefreshToken } = await import('./token-service.js')

beforeEach(async () => {
  const pair = await generateKeyPair('RS256')
  state.keys.privateKey = pair.privateKey
  state.keys.jwks = {
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'fixture-kid', alg: 'RS256' }],
  }
  state.created.length = 0
  state.revokedSessions.length = 0
  state.audits.length = 0
  state.groupRoles = []
  state.stored = {
    tokenHash: 'fixture',
    userId: 'fixture-user',
    sessionId: 'fixture-session',
    clientId: null,
    revokedAt: null,
    expiresAt: new Date(Date.now() + 3_600_000),
  }
  state.session = { userId: 'fixture-user', revokedAt: null, expiresAt: new Date(Date.now() + 7_200_000) }
  state.client = { active: true, clientType: 'public', grantTypes: '["authorization_code","refresh_token"]' }
})

it('rotates a native refresh token inside its active session', async () => {
  const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1')
  expect(decodeJwt(pair.accessToken)).toMatchObject({
    sub: 'fixture-user',
    iss: 'https://identity.example.com',
    sessionId: 'fixture-session',
    permissions: ['example:read', 'example:write'],
  })
  expect(state.created).toMatchObject([{ clientId: null, sessionId: 'fixture-session' }])
})

it.each(['hivexui-example', 'example-worker', 'hive-router'])(
  'never lets the request choose the client of an unbound refresh token (%s)',
  async (requested) => {
    const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1', requested)
    const claims = decodeJwt(pair.accessToken)
    expect(claims).not.toHaveProperty('clientId')
    expect(claims).not.toHaveProperty('aud')
    expect(claims.iss).toBe('https://identity.example.com')
    expect(state.created).toMatchObject([{ clientId: null, sessionId: 'fixture-session' }])
  },
)

it('keeps the client a refresh token was issued to', async () => {
  state.stored!.clientId = 'example-worker'
  const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1', 'example-worker')
  expect(decodeJwt(pair.accessToken)).toMatchObject({
    clientId: 'example-worker',
    aud: 'example-api',
  })
  state.stored!.revokedAt = null
  await expect(
    rotateRefreshToken('fixture-refresh', '192.0.2.1', 'hivexui-example'),
  ).rejects.toMatchObject({ status: 401, code: 'TOKEN_BINDING_MISMATCH' })
})

it('does not consume the token when another client presents it', async () => {
  state.stored!.clientId = 'example-worker'
  await expect(
    rotateRefreshToken('fixture-refresh', '192.0.2.1', 'hivexui-example'),
  ).rejects.toMatchObject({ code: 'TOKEN_BINDING_MISMATCH' })
  expect(state.stored!.revokedAt).toBeNull()
  // The rightful client can still rotate it.
  await rotateRefreshToken('fixture-refresh', '192.0.2.1', 'example-worker')
  expect(state.created).toHaveLength(1)
})

it('carries the permissions of roles the user holds through a group', async () => {
  state.groupRoles = [{ name: 'GROUP_OPS', permissions: JSON.stringify(['ops:deploy', 'example:read']) }]
  const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1')
  expect(decodeJwt(pair.accessToken)).toMatchObject({
    roles: ['EXAMPLE', 'GROUP_OPS'],
    permissions: ['example:read', 'example:write', 'ops:deploy'],
  })
})

it('refuses refresh after the session hard expiry and keeps the token unconsumed', async () => {
  state.session!.expiresAt = new Date(Date.now() - 1000)
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({
    status: 401,
    code: 'INVALID_REFRESH_TOKEN',
  })
  expect(state.created).toEqual([])
})

it('never issues a refresh token that outlives its session', async () => {
  const sessionEnd = new Date(Date.now() + 60_000)
  state.session!.expiresAt = sessionEnd
  await rotateRefreshToken('fixture-refresh')
  expect(state.created[0]!.expiresAt!.getTime()).toBe(sessionEnd.getTime())
})

it('requires a confidential client to have authenticated, before consuming the token', async () => {
  state.stored!.clientId = 'example-worker'
  state.client = { active: true, clientType: 'confidential', grantTypes: '["authorization_code","refresh_token"]' }
  await expect(rotateRefreshToken('fixture-refresh', undefined, 'example-worker')).rejects.toMatchObject({
    status: 401,
    code: 'INVALID_CLIENT',
  })
  expect(state.stored!.revokedAt).toBeNull()
  await rotateRefreshToken('fixture-refresh', undefined, 'example-worker', undefined, { clientAuthenticated: true })
  expect(state.created).toHaveLength(1)
})

it('refuses a client that is inactive or no longer has the refresh_token grant', async () => {
  state.stored!.clientId = 'example-worker'
  state.client = { active: false, clientType: 'public', grantTypes: '["authorization_code","refresh_token"]' }
  await expect(rotateRefreshToken('fixture-refresh', undefined, 'example-worker')).rejects.toMatchObject({
    code: 'INVALID_CLIENT',
  })
  state.client = { active: true, clientType: 'public', grantTypes: '["authorization_code"]' }
  await expect(rotateRefreshToken('fixture-refresh', undefined, 'example-worker')).rejects.toMatchObject({
    code: 'UNAUTHORIZED_CLIENT',
  })
  expect(state.created).toEqual([])
})

it('revokes the session when a rotated refresh token is replayed', async () => {
  await rotateRefreshToken('fixture-refresh')
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({
    status: 401,
    code: 'INVALID_REFRESH_TOKEN',
  })
  expect(state.revokedSessions).toEqual(['fixture-session'])
  expect(state.audits).toEqual(['token.refresh_reuse'])
  // A replay against a session that is already revoked changes nothing further.
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({ status: 401 })
  expect(state.revokedSessions).toEqual(['fixture-session'])
})

it('refuses a refresh token whose session was revoked', async () => {
  state.session = { userId: 'fixture-user', revokedAt: new Date(), expiresAt: new Date(Date.now() + 60_000) }
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({
    status: 401,
    code: 'INVALID_REFRESH_TOKEN',
  })
  expect(state.created).toEqual([])
})

it('refuses a refresh token whose session belongs to another account or is gone', async () => {
  state.session = { userId: 'another-user', revokedAt: null, expiresAt: new Date(Date.now() + 60_000) }
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({ status: 401 })
  state.session = null
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({ status: 401 })
  expect(state.created).toEqual([])
})
