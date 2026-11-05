import { Hono, type Context, type Next } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'

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
  verifyPassword: vi.fn(async () => false),
  publish: vi.fn(async () => {}),
  audit: vi.fn(async () => {}),
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
  verifyTotpCode: () => false,
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
  issueTokenPair: vi.fn(),
  rotateRefreshToken: vi.fn(),
  revokeRefreshToken: vi.fn(),
  introspectToken: vi.fn(),
}))
vi.mock('../services/session-service.js', () => ({
  createSession: vi.fn(),
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

/** Route limits are fixed at import, so each mode loads its own router. */
async function application(relaxed: boolean) {
  state.env.RELAX_AUTH_LIMITS = relaxed
  vi.resetModules()
  const { authRouter } = await import('./auth.js')
  const { passwordPolicyRouter } = await import('./password-policy.js')
  const { errorHandler } = await import('../middleware/error-handler.js')
  const app = new Hono()
  app.onError(errorHandler)
  app.route('/auth', authRouter)
  app.route('/password-policy', passwordPolicyRouter)
  return app
}
const post = (app: Hono, path: string, body: unknown) =>
  app.request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
const badPassword = (app: Hono) =>
  post(app, '/auth/login', { username: 'alice', password: 'obviously-wrong' })
const badCode = (app: Hono) =>
  post(app, '/auth/mfa/challenge', {
    mfaToken: 'fake-token',
    code: '000000',
  })

function assertPolicyUnwritten() {
  for (const write of [
    state.passwordPolicy.create,
    state.passwordPolicy.update,
    state.passwordPolicy.updateMany,
    state.passwordPolicy.upsert,
    state.passwordPolicy.delete,
    state.passwordPolicy.deleteMany,
  ])
    expect(write).not.toHaveBeenCalled()
}

beforeEach(() => {
  vi.clearAllMocks()
  state.redisCount = 0
  state.user.findFirst.mockResolvedValue({ ...account })
  state.user.findUnique.mockResolvedValue({ ...account })
  state.passwordPolicy.findFirst.mockResolvedValue(storedPolicy)
  state.verifyPassword.mockResolvedValue(false)
})

describe('failed passwords by default', () => {
  it('count against the account and lock it at the configured limit', async () => {
    const app = await application(false)
    expect((await badPassword(app)).status).toBe(401)
    expect(state.user.update).toHaveBeenLastCalledWith({
      where: { id: 'fake-user' },
      data: { failedAttempts: 1 },
    })
    expect(state.publish).not.toHaveBeenCalled()

    state.user.findFirst.mockResolvedValue({ ...account, failedAttempts: 4 })
    expect((await badPassword(app)).status).toBe(401)
    expect(state.user.update).toHaveBeenLastCalledWith({
      where: { id: 'fake-user' },
      data: { failedAttempts: 5, lockedUntil: expect.any(Date) },
    })
    expect(state.publish).toHaveBeenCalledWith(
      'auth.lockout',
      expect.objectContaining({ userId: 'fake-user', attempts: 5 }),
    )
  })

  it('refuse a failure-locked account before checking its password', async () => {
    const app = await application(false)
    state.user.findFirst.mockResolvedValue({
      ...account,
      lockedUntil: new Date(Date.now() + 60_000),
    })
    expect((await badPassword(app)).status).toBe(401)
    expect(state.verifyPassword).not.toHaveBeenCalled()
  })

  it('throttle the sixth sign-in attempt', async () => {
    const app = await application(false)
    for (let index = 1; index <= 5; index++)
      expect((await badPassword(app)).status).toBe(401)
    expect((await badPassword(app)).status).toBe(429)
  })
})

describe('failed passwords when relaxed', () => {
  it('leave the account untouched and still audit each failure', async () => {
    const app = await application(true)
    state.user.findFirst.mockResolvedValue({ ...account, failedAttempts: 4 })
    expect((await badPassword(app)).status).toBe(401)
    expect(state.user.update).not.toHaveBeenCalled()
    expect(state.publish).not.toHaveBeenCalled()
    expect(state.audit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'auth.login.failed',
        detail: expect.objectContaining({ authLimitsRelaxed: true }),
      }),
    )
  })

  it('still reject the wrong password far beyond the default limit', async () => {
    const app = await application(true)
    for (let index = 1; index <= 25; index++)
      expect((await badPassword(app)).status).toBe(401)
    expect(state.verifyPassword).toHaveBeenCalledTimes(25)
    expect(state.user.update).not.toHaveBeenCalled()
  })

  it('throttle only beyond the relaxed ceiling', async () => {
    const app = await application(true)
    state.redisCount = 9_999
    expect((await badPassword(app)).status).toBe(401)
    expect((await badPassword(app)).status).toBe(429)
  })

  it('look past a failure lock but enforce an administrator lock', async () => {
    const app = await application(true)
    state.user.findFirst.mockResolvedValue({
      ...account,
      lockedUntil: new Date(Date.now() + 60_000),
    })
    await badPassword(app)
    expect(state.verifyPassword).toHaveBeenCalledTimes(1)

    state.user.findFirst.mockResolvedValue({
      ...account,
      lockedUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    })
    expect((await badPassword(app)).status).toBe(401)
    expect(state.verifyPassword).toHaveBeenCalledTimes(1)
  })
})

describe('second-factor attempts', () => {
  it('lock and throttle by default', async () => {
    const app = await application(false)
    state.user.findUnique.mockResolvedValue({ ...account, failedAttempts: 4 })
    expect((await badCode(app)).status).toBe(401)
    expect(state.user.update).toHaveBeenLastCalledWith({
      where: { id: 'fake-user' },
      data: { failedAttempts: 5, lockedUntil: expect.any(Date) },
    })
    state.redisCount = 5
    expect((await badCode(app)).status).toBe(429)
  })

  it('neither lock nor throttle at the default limit when relaxed', async () => {
    const app = await application(true)
    state.user.findUnique.mockResolvedValue({ ...account, failedAttempts: 4 })
    state.redisCount = 5
    expect((await badCode(app)).status).toBe(401)
    expect(state.user.update).not.toHaveBeenCalled()
  })

  it('apply to step-up as well', async () => {
    const strict = await application(false)
    state.redisCount = 5
    expect(
      (await post(strict, '/auth/step-up', { password: 'obviously-wrong' })).status,
    ).toBe(429)
    const relaxed = await application(true)
    state.redisCount = 5
    expect(
      (await post(relaxed, '/auth/step-up', { password: 'obviously-wrong' })).status,
    ).not.toBe(429)
  })
})

describe('password recovery when relaxed', () => {
  it('keeps its own throttles', async () => {
    const app = await application(true)
    state.redisCount = 5
    expect(
      (await post(app, '/auth/forgot-password', { email: 'alice@example.com' }))
        .status,
    ).toBe(429)
    state.redisCount = 10
    expect(
      (
        await post(app, '/auth/reset-password', {
          token: 'fake-token',
          newPassword: 'obviously-fake-password',
        })
      ).status,
    ).toBe(429)
  })
})

describe('the stored password policy', () => {
  it('is neither rewritten nor reported differently in either mode', async () => {
    for (const relaxed of [false, true]) {
      const app = await application(relaxed)
      await badPassword(app)
      await badCode(app)
      const response = await app.request('/password-policy')
      expect(response.status).toBe(200)
      expect(await response.json()).toMatchObject({
        policy: { lockoutAttempts: 5, lockoutDurationMin: 30 },
      })
    }
    assertPolicyUnwritten()
  })
})
