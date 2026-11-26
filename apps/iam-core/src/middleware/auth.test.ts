import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock the token service before importing the middleware
vi.mock('../services/token-service.js', () => ({
  verifyAccessToken: vi.fn(),
}))

import { Hono } from 'hono'
import { authMiddleware } from './auth.js'
import { verifyAccessToken } from '../services/token-service.js'

const mockedVerify = vi.mocked(verifyAccessToken)

function createApp() {
  const app = new Hono()
  app.use('*', authMiddleware)
  app.get('/protected', (c) => {
    const principal = c.get('principal')
    return c.json({ sub: principal.sub, email: principal.email })
  })
  return app
}

describe('authMiddleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns 401 when no Authorization header', async () => {
    const app = createApp()
    const res = await app.request('/protected')
    expect(res.status).toBe(401)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('UNAUTHORIZED')
    expect(body.message).toContain('Bearer')
  })

  it('returns 401 when Authorization is not Bearer', async () => {
    const app = createApp()
    const res = await app.request('/protected', {
      headers: { Authorization: 'Basic abc123' },
    })
    expect(res.status).toBe(401)
  })

  it('sets principal on valid token', async () => {
    mockedVerify.mockResolvedValue({
      sub: 'user-42',
      actorType: 'USER',
      email: 'alice@example.com',
      username: 'alice',
      roles: ['ADMIN'],
      permissions: ['iam:users:read', 'iam:users:write'],
      sessionId: 'sess-1',
      jti: 'jti-1',
      iss: 'iam-core',
      iat: 0,
      exp: 0,
    })

    const app = createApp()
    const res = await app.request('/protected', {
      headers: { Authorization: 'Bearer valid-token' },
    })

    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.sub).toBe('user-42')
    expect(body.email).toBe('alice@example.com')
    expect(mockedVerify).toHaveBeenCalledWith('valid-token')
  })

  it('returns 401 when token is invalid', async () => {
    mockedVerify.mockRejectedValue(new Error('jwt expired'))

    const app = createApp()
    const res = await app.request('/protected', {
      headers: { Authorization: 'Bearer expired-token' },
    })

    expect(res.status).toBe(401)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('UNAUTHORIZED')
  })

  describe('the Router client token', () => {
    const router = {
      sub: 'hive-router',
      actorType: 'SERVICE_ACCOUNT',
      clientId: 'hive-router',
      roles: [],
      permissions: ['iam:users:read', 'iam:users:write'],
      jti: 'fixture',
    }
    function routerApp() {
      const app = new Hono()
      app.use('*', authMiddleware)
      app.get('/users', (c) => c.json({ ok: true }))
      app.post('/users', (c) => c.json({ ok: true }))
      app.delete('/users/x', (c) => c.json({ ok: true }))
      return app
    }
    const operator = JSON.stringify({ id: 'console-operator', sessionId: 's', authenticatedAt: 1, authMode: 'os' })

    it('reads without operator attribution', async () => {
      mockedVerify.mockResolvedValue(router as never)
      expect((await routerApp().request('/users', { headers: { Authorization: 'Bearer router-token' } })).status).toBe(200)
    })

    it('refuses a write that names no console operator', async () => {
      mockedVerify.mockResolvedValue(router as never)
      for (const [method, path, header] of [
        ['POST', '/users', undefined],
        ['DELETE', '/users/x', undefined],
        ['POST', '/users', 'not json'],
        ['POST', '/users', JSON.stringify({ authMode: 'os' })],
      ] as const) {
        const res = await routerApp().request(path, {
          method,
          headers: { Authorization: 'Bearer router-token', ...(header ? { 'x-hive-operator': header } : {}) },
        })
        expect(res.status).toBe(403)
        expect(((await res.json()) as Record<string, unknown>).error).toBe('ROUTER_OPERATOR_REQUIRED')
      }
    })

    it('admits a write attributed to an operator, and never restricts other clients', async () => {
      mockedVerify.mockResolvedValue(router as never)
      expect((await routerApp().request('/users', { method: 'POST', headers: { Authorization: 'Bearer router-token', 'x-hive-operator': operator } })).status).toBe(200)
      mockedVerify.mockResolvedValue({ ...router, sub: 'other-service', clientId: 'other-service' } as never)
      expect((await routerApp().request('/users', { method: 'POST', headers: { Authorization: 'Bearer other-token' } })).status).toBe(200)
    })
  })
})
