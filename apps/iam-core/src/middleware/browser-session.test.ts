import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { exportJWK, generateKeyPair } from 'jose'
import { ApiError } from '../types/index.js'

const mocks = vi.hoisted(() => ({
  active: true,
  deleted: vi.fn(),
  revoked: vi.fn(),
  keys: null as unknown as Awaited<ReturnType<typeof generateKeyPair>>,
  jwks: { keys: [] } as { keys: object[] },
}))
vi.mock('../config/env.js', () => ({
  env: {
    CORS_ORIGIN: 'https://console.example.com',
    JWT_ISSUER: 'https://identity.example.com',
    JWT_REFRESH_TTL: 3600,
  },
}))
vi.mock('../utils/keys.js', () => ({
  getPrivateKey: async () => mocks.keys.privateKey,
  getSigningKeyId: async () => 'test',
  getPublishedSigningJwks: async () => mocks.jwks,
}))
vi.mock('../services/token-service.js', () => ({
  verifyAccessToken: async () => ({
    sub: 'fake-user',
    actorType: 'USER',
    sessionId: 'fake-session',
    roles: [],
    permissions: [],
  }),
}))
vi.mock('./auth.js', () => ({
  authMiddleware: (c: { json: (body: object, status: number) => Response }) =>
    c.json({ error: 'invalid bearer' }, 401),
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    refreshToken: { deleteMany: mocks.deleted },
    session: {
      updateMany: mocks.revoked,
      findFirst: async () =>
        mocks.active
          ? {
              id: 'fake-session',
              userId: 'fake-user',
              user: {
                email: 'alice@example.com',
                username: 'alice',
                roles: [],
              },
            }
          : null,
    },
  },
}))
import {
  establishBrowserSession,
  browserAuthorization,
  clearBrowserSession,
} from './browser-session.js'

function app() {
  const app = new Hono()
  app.onError((error, c) =>
    c.json(
      { error: 'denied' },
      error instanceof ApiError ? (error.status as 403) : 500,
    ),
  )
  app.use('/login', establishBrowserSession)
  app.post('/login', (c) => {
    c.header(
      'Set-Cookie',
      'iam_refresh=obviously-fake-refresh; Secure; HttpOnly',
    )
    return c.json({
      accessToken: 'obviously-fake-access',
      refreshToken: 'obviously-fake-refresh',
    })
  })
  app.get('/authorize', browserAuthorization, (c) =>
    c.json({ sub: c.get('principal').sub }),
  )
  app.post('/logout', async (c) => {
    await clearBrowserSession(c)
    return c.json({ ok: true })
  })
  return app
}
describe('browser SSO session transport', () => {
  beforeAll(async () => {
    mocks.keys = await generateKeyPair('RS256')
    mocks.jwks = {
      keys: [{ ...(await exportJWK(mocks.keys.publicKey)), kid: 'test' }],
    }
  })
  beforeEach(() => {
    mocks.active = true
    mocks.deleted.mockClear()
    mocks.revoked.mockClear()
  })
  async function login() {
    const response = await app().request('/login', {
      method: 'POST',
      headers: {
        Origin: 'https://console.example.com',
        'X-Oathweave-Browser': 'true',
      },
    })
    expect(response.status).toBe(200)
    return response
  }
  it('replaces refresh credentials with a secure server-owned SSO cookie', async () => {
    const response = await login()
    expect(await response.json()).toEqual({
      accessToken: 'obviously-fake-access',
    })
    expect(response.headers.get('set-cookie')).toMatch(/^__Host-oathweave_sso=/)
    expect(response.headers.get('set-cookie')).toContain('HttpOnly')
    expect(response.headers.get('set-cookie')).toContain('SameSite=Strict')
    expect(response.headers.get('set-cookie')).not.toContain('iam_refresh')
    expect(mocks.deleted).toHaveBeenCalledOnce()
  })
  it('rejects login CSRF before credential handling', async () => {
    const response = await app().request('/login', {
      method: 'POST',
      headers: {
        Origin: 'https://untrusted.example.com',
        'X-Oathweave-Browser': 'true',
      },
    })
    expect(response.status).toBe(403)
    expect(mocks.deleted).not.toHaveBeenCalled()
  })
  it('checks session revocation on each authorization and ignores cookie fallback for an invalid bearer', async () => {
    const response = await login()
    const cookie = response.headers.get('set-cookie')!.split(';')[0]!
    expect(
      (await app().request('/authorize', { headers: { Cookie: cookie } }))
        .status,
    ).toBe(200)
    expect(
      (
        await app().request('/authorize', {
          headers: {
            Cookie: cookie,
            Authorization: 'Bearer obviously-fake-invalid',
          },
        })
      ).status,
    ).toBe(401)
    mocks.active = false
    expect(
      (await app().request('/authorize', { headers: { Cookie: cookie } }))
        .status,
    ).toBe(401)
  })
  it('requires an allowed origin for logout and revokes the exact session', async () => {
    const response = await login()
    const cookie = response.headers.get('set-cookie')!.split(';')[0]!
    expect(
      (
        await app().request('/logout', {
          method: 'POST',
          headers: { Cookie: cookie },
        })
      ).status,
    ).toBe(403)
    expect(
      (
        await app().request('/logout', {
          method: 'POST',
          headers: { Cookie: cookie, Origin: 'https://console.example.com' },
        })
      ).status,
    ).toBe(200)
    expect(mocks.revoked).toHaveBeenCalledWith({
      where: { id: 'fake-session', userId: 'fake-user' },
      data: { revokedAt: expect.any(Date) },
    })
  })
})
