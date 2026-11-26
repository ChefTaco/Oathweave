import { Hono, type Context, type Next } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Sign-in and the MFA challenge issue tokens with the user's effective grants (direct and group).

const state = vi.hoisted(() => ({
  env: {
    RELAX_AUTH_LIMITS: false,
    RATE_LIMIT_WINDOW_MS: 900_000,
    RATE_LIMIT_MAX_ATTEMPTS: 5,
    REDIS_PREFIX: 'fixture',
    JWT_ISSUER: 'https://identity.example.com',
    JWT_ACCESS_TTL: 900,
    NODE_ENV: 'test',
  },
  redisCount: 0,
  user: {
    findFirst: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(async () => ({})),
    updateMany: vi.fn(async () => ({ count: 1 })),
  },
  passwordPolicy: {
    findFirst: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    updateMany: vi.fn(),
    upsert: vi.fn(),
    delete: vi.fn(),
    deleteMany: vi.fn(),
  },
  verifyPassword: vi.fn(async () => true),
  issued: [] as { roles: unknown; permissions: unknown }[],
  publish: vi.fn(async () => {}),
  audit: vi.fn(async () => {}),
}))
// Direct role VIEWER plus OPERATOR inherited from a group: the effective grants a token carries.
vi.mock('../services/effective-grants.js', () => ({
  userTokenGrants: vi.fn(async () => ({
    roles: ['VIEWER', 'OPERATOR'],
    permissions: ['example:read', 'example:deploy'],
  })),
}))
vi.mock('../config/env.js', () => ({ env: state.env }))
vi.mock('../db/client.js', () => ({
  prisma: { user: state.user, passwordPolicy: state.passwordPolicy },
}))
vi.mock('../queue/audit-queue.js', () => ({
  redisConnection: {
    pipeline: () => ({
      zremrangebyscore: () => undefined,
      zadd: () => undefined,
      zcard: () => undefined,
      pexpire: () => undefined,
      exec: async () => [null, null, [null, ++state.redisCount], null],
    }),
    set: vi.fn(),
  },
}))
vi.mock('../utils/ip.js', () => ({ getClientIp: () => '203.0.113.7' }))
vi.mock('../middleware/auth.js', () => ({
  authMiddleware: async (_c: Context, next: Next) => next(),
}))
vi.mock('../middleware/browser-session.js', () => ({
  browserAuthorization: async (_c: Context, next: Next) => next(),
}))
vi.mock('../services/login-challenge.js', () => ({
  loginChallengeUser: async () => 'fake-user',
  consumeLoginChallenge: async () => {},
}))
vi.mock('../services/mfa-service.js', () => ({
  verifyTotpCode: () => true,
  consumeTotpCode: async () => true,
  verifyBackupCode: async () => -1,
  generateTotpSecret: vi.fn(),
  generateBackupCodes: vi.fn(),
}))
vi.mock('../services/password-service.js', () => ({
  verifyPassword: state.verifyPassword,
  hashPassword: vi.fn(),
}))
vi.mock('../services/audit-service.js', () => ({ logAuditEvent: state.audit }))
vi.mock('../services/event-bus.js', () => ({
  eventBus: { publish: state.publish },
}))
vi.mock('../services/token-service.js', () => ({
  issueTokenPair: vi.fn(async (...args: unknown[]) => {
    state.issued.push({ roles: args[3], permissions: args[4] })
    return { accessToken: 'fake-access', refreshToken: 'fake-refresh', sessionId: 'fake-session', expiresIn: 900 }
  }),
  rotateRefreshToken: vi.fn(),
  revokeRefreshToken: vi.fn(),
}))
vi.mock('../services/session-service.js', () => ({
  createSession: vi.fn(async () => ({ sessionId: 'fake-session', riskScore: 0, riskFactors: [] })),
  revokeSession: vi.fn(),
}))
vi.mock('../services/session-risk-service.js', () => ({
  computeSessionRisk: vi.fn(),
}))
vi.mock('../services/breach-check-service.js', () => ({
  checkBreachedPassword: vi.fn(),
}))
vi.mock('../services/recovery-delivery.js', () => ({
  recoveryOutbox: vi.fn(async () => '/opt/example/recovery'),
  deliverPasswordRecovery: vi.fn(),
}))
vi.mock('../services/step-up-mfa.js', () => ({
  stepUpPasskeyOptions: vi.fn(),
  verifyStepUpPasskey: vi.fn(),
}))
vi.mock('../middleware/step-up.js', () => ({
  completeStepUp: vi.fn(),
  requireStepUp: () => async (_c: Context, next: Next) => next(),
}))
vi.mock('../middleware/recent-session.js', () => ({
  requireRecentSession: async (_c: Context, next: Next) => next(),
}))
vi.mock('../utils/keys.js', () => ({
  getPrivateKey: vi.fn(),
  getPublicKeyPem: vi.fn(),
  getPublicKey: vi.fn(),
}))

const storedPolicy = {
  id: 'fake-policy',
  name: 'Default Policy',
  isDefault: true,
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecial: true,
  maxAgeDays: 0,
  historyCount: 5,
  lockoutAttempts: 5,
  lockoutDurationMin: 30,
}
const account = {
  id: 'fake-user',
  email: 'alice@example.com',
  username: 'alice',
  active: true,
  passwordHash: 'fake-password-hash',
  failedAttempts: 0,
  lockedUntil: null as Date | null,
  mfaEnabled: true,
  mfaSecret: 'fake-mfa-secret',
  mfaVerifiedAt: new Date(0),
  mfaBackupCodes: '[]',
  passwordChangedAt: null,
  allowedIps: '[]',
  roles: [],
  webauthnCredentials: [],
}


const { authRouter } = await import('./auth.js')
const { errorHandler } = await import('../middleware/error-handler.js')
const { userTokenGrants } = await import('../services/effective-grants.js')
const app = new Hono().route('/auth', authRouter).onError(errorHandler)
const post = (path: string, body: unknown) =>
  app.request(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
const effective = { roles: ['VIEWER', 'OPERATOR'], permissions: ['example:read', 'example:deploy'] }

beforeEach(() => {
  state.issued.length = 0
  state.redisCount = 0
  state.passwordPolicy.findFirst.mockResolvedValue(storedPolicy)
  vi.mocked(userTokenGrants).mockClear()
})

describe('tokens carry group-derived grants', () => {
  it('on password sign-in', async () => {
    state.user.findFirst.mockResolvedValue({ ...account, mfaEnabled: false })
    const response = await post('/auth/login', { username: 'alice', password: 'fixture-password' })
    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ user: effective })
    expect(userTokenGrants).toHaveBeenCalledWith('fake-user')
    expect(state.issued).toEqual([effective])
  })

  it('on the MFA challenge', async () => {
    state.user.findUnique.mockResolvedValue({ ...account })
    const response = await post('/auth/mfa/challenge', { mfaToken: 'fake-token', code: '123456' })
    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ user: effective })
    expect(state.issued).toEqual([effective])
  })
})
