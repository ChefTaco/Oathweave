import { Hono, type MiddlewareHandler } from 'hono'
import { beforeEach, expect, it, vi } from 'vitest'
import { errorHandler } from '../middleware/error-handler.js'
const mocks = vi.hoisted(() => ({
  validate: vi.fn(async () => ({
    skipConsent: false,
    clientName: 'Example console',
    clientDescription: null,
    scope: 'openid profile',
  })),
  create: vi.fn(async (_user: string, _params: unknown, _ip?: string) => ({
    code: 'fake-code',
    state: 'fake-state',
    skipConsent: false,
  })),
  audit: vi.fn(),
}))
vi.mock('../db/client.js', () => ({ prisma: {} }))
vi.mock('../config/env.js', () => ({
  env: { JWT_ISSUER: 'https://identity.example.com' },
}))
vi.mock('../services/browser-policies.js', () => ({
  browserClientPolicies: {
    'hivexui-example': { audience: 'example', permissions: ['example:read'] },
  },
  issuerForClient: () => 'https://identity.example.com',
}))
vi.mock('../middleware/browser-session.js', () => ({
  requireBrowserOrigin: vi.fn(),
  browserAuthorization: (async (c, next) => {
    c.set('principal', {
      sub: 'fake-user',
      actorType: 'USER',
      roles: [],
      permissions: ['example:read'],
      sessionId: 'fake-session',
      clientId: undefined,
    })
    await next()
  }) satisfies MiddlewareHandler,
}))
vi.mock('../services/oauth-service.js', () => ({
  validateAuthorizeRequest: mocks.validate,
  createAuthorizationCode: mocks.create,
  exchangeAuthorizationCode: vi.fn(),
  exchangeClientCredentials: vi.fn(),
  getOpenIdConfiguration: vi.fn(),
  getJwks: vi.fn(),
}))
vi.mock('../services/token-service.js', () => ({
  rotateRefreshToken: vi.fn(),
  issueIdToken: vi.fn(),
  verifyAccessToken: vi.fn(),
}))
vi.mock('../services/audit-service.js', () => ({ logAuditEvent: mocks.audit }))
const { oauthRouter } = await import('./oauth.js')
const app = new Hono().route('/oauth', oauthRouter).onError(errorHandler)
const send = (consent?: string) =>
  app.request('/oauth/authorize', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Oathweave-Browser': 'true',
      Origin: 'https://console.example.com',
    },
    body: JSON.stringify({
      clientId: 'hivexui-example',
      redirectUri: 'https://console.example.com/auth/callback',
      responseType: 'code',
      codeChallenge: 'a'.repeat(43),
      codeChallengeMethod: 'S256',
      state: 'fake-state',
      ...(consent ? { consent } : {}),
    }),
  })
beforeEach(() => {
  mocks.create.mockClear()
  mocks.validate.mockClear()
})
it('returns the exact audience and permissions without creating any code before consent', async () => {
  const response = await send()
  expect(response.status).toBe(403)
  expect(await response.json()).toMatchObject({
    error: 'CONSENT_REQUIRED',
    audience: 'example',
    permissions: ['example:read'],
  })
  expect(mocks.create).not.toHaveBeenCalled()
})
it('declining allocates no code; explicit approval creates one bound to the browser session', async () => {
  expect((await send('deny')).status).toBe(403)
  expect(mocks.create).not.toHaveBeenCalled()
  const response = await send('approve')
  expect(response.status).toBe(200)
  expect(mocks.create).toHaveBeenCalledOnce()
  expect(mocks.create.mock.calls[0]?.[1]).toMatchObject({
    clientId: 'hivexui-example',
    browserSessionId: 'fake-session',
  })
  expect(response.headers.get('cache-control')).toBe('no-store')
})
it('answers a malformed JSON token request with an OAuth error instead of a server fault', async () => {
  const response = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"grant_type":',
  })
  expect(response.status).toBe(400)
  expect(await response.json()).toMatchObject({ error: 'invalid_request' })
})
