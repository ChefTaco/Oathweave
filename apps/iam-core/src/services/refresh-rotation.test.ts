import { beforeEach, expect, it, vi } from 'vitest'
import { decodeJwt, exportJWK, generateKeyPair } from 'jose'

const state = vi.hoisted(() => ({
  stored: null as null | {
    tokenHash: string
    userId: string
    sessionId: string | null
    clientId: string | null
  },
  session: null as null | { userId: string; revokedAt: Date | null },
  created: [] as { clientId: string | null; sessionId: string }[],
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
vi.mock('../utils/keys.js', () => ({
  getPrivateKey: async () => state.keys.privateKey,
  getSigningKeyId: async () => 'fixture-kid',
  getPublishedSigningJwks: async () => state.keys.jwks,
}))
vi.mock('./session-service.js', () => ({
  createSession: vi.fn(async () => ({ sessionId: 'fresh-session' })),
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    refreshToken: {
      updateMany: vi.fn(async () => ({ count: state.stored ? 1 : 0 })),
      findUnique: vi.fn(async () => state.stored),
      create: vi.fn(
        async ({ data }: { data: { clientId: string | null; sessionId: string } }) => {
          state.created.push({ clientId: data.clientId, sessionId: data.sessionId })
          return data
        },
      ),
    },
    session: { findUnique: vi.fn(async () => state.session) },
    user: {
      findUnique: vi.fn(async () => ({
        id: 'fixture-user',
        email: 'person@example.com',
        username: 'person',
        active: true,
        roles: [
          {
            role: {
              name: 'EXAMPLE',
              permissions: JSON.stringify(['example:read', 'example:write']),
            },
          },
        ],
      })),
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
  state.stored = {
    tokenHash: 'fixture',
    userId: 'fixture-user',
    sessionId: 'fixture-session',
    clientId: null,
  }
  state.session = { userId: 'fixture-user', revokedAt: null }
})

it('rotates a native refresh token inside its active session', async () => {
  const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1')
  expect(decodeJwt(pair.accessToken)).toMatchObject({
    sub: 'fixture-user',
    iss: 'https://identity.example.com',
    sessionId: 'fixture-session',
    permissions: ['example:read', 'example:write'],
  })
  expect(state.created).toEqual([{ clientId: null, sessionId: 'fixture-session' }])
})

it.each(['hivexui-example', 'example-worker', 'hive-router'])(
  'never lets the request choose the client of an unbound refresh token (%s)',
  async (requested) => {
    const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1', requested)
    const claims = decodeJwt(pair.accessToken)
    expect(claims).not.toHaveProperty('clientId')
    expect(claims).not.toHaveProperty('aud')
    expect(claims.iss).toBe('https://identity.example.com')
    expect(state.created).toEqual([{ clientId: null, sessionId: 'fixture-session' }])
  },
)

it('keeps the client a refresh token was issued to', async () => {
  state.stored!.clientId = 'example-worker'
  const pair = await rotateRefreshToken('fixture-refresh', '192.0.2.1', 'example-worker')
  expect(decodeJwt(pair.accessToken)).toMatchObject({
    clientId: 'example-worker',
    aud: 'example-api',
  })
  await expect(
    rotateRefreshToken('fixture-refresh', '192.0.2.1', 'hivexui-example'),
  ).rejects.toMatchObject({ status: 401, code: 'TOKEN_BINDING_MISMATCH' })
})

it('refuses a refresh token whose session was revoked', async () => {
  state.session = { userId: 'fixture-user', revokedAt: new Date() }
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({
    status: 401,
    code: 'INVALID_REFRESH_TOKEN',
  })
  expect(state.created).toEqual([])
})

it('refuses a refresh token whose session belongs to another account or is gone', async () => {
  state.session = { userId: 'another-user', revokedAt: null }
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({ status: 401 })
  state.session = null
  await expect(rotateRefreshToken('fixture-refresh')).rejects.toMatchObject({ status: 401 })
  expect(state.created).toEqual([])
})
