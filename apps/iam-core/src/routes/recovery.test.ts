import { Hono, type Context, type Next } from 'hono'
import { beforeEach, expect, it, vi } from 'vitest'
import { ApiError } from '../types/index.js'
import { errorHandler } from '../middleware/error-handler.js'
const mock = vi.hoisted(() => ({
  principal: {
    sub: 'fake-user',
    actorType: 'USER',
    clientId: 'hivexui-reader',
    roles: ['reader'],
    permissions: ['iam:users:read'],
  },
  claimed: false,
  challenge: vi.fn(async () => 'fake-user'),
  consumeChallenge: vi.fn(async () => {}),
  user: { findUnique: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
  passwordResetToken: {
    findFirst: vi.fn(),
    updateMany: vi.fn(),
    create: vi.fn(),
  },
  session: { updateMany: vi.fn() },
  refreshToken: { deleteMany: vi.fn() },
  authorizationCode: { deleteMany: vi.fn() },
  outbox: vi.fn(async () => '/opt/private/recovery'),
  deliver: vi.fn(),
  audit: vi.fn(),
}))
vi.mock('../middleware/auth.js', () => ({
  authMiddleware: async (c: Context, next: Next) => {
    c.set('principal', mock.principal as never)
    await next()
  },
}))
vi.mock('../services/browser-policies.js', async (original) => ({
  ...(await original<typeof import('../services/browser-policies.js')>()),
  browserClientPolicies: {
    'hivexui-reader': {
      audience: 'oathweave',
      permissions: ['iam:users:read'],
    },
  },
}))
vi.mock('../services/login-challenge.js', () => ({
  loginChallengeUser: mock.challenge,
  consumeLoginChallenge: mock.consumeChallenge,
}))
vi.mock('../services/mfa-service.js', () => ({
  verifyBackupCode: async () => 0,
  verifyTotpCode: () => false,
  generateTotpSecret: vi.fn(),
  generateBackupCodes: vi.fn(),
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    ...mock,
    $transaction: async (callback: (database: unknown) => Promise<unknown>) =>
      callback(mock),
  },
}))
vi.mock('../config/env.js', () => ({ env: {} }))
vi.mock('../queue/audit-queue.js', () => ({
  redisConnection: { set: vi.fn() },
}))
vi.mock('../middleware/rate-limit.js', () => ({
  rateLimitMiddleware: () => async (_c: unknown, next: () => Promise<void>) =>
    next(),
}))
vi.mock('../services/audit-service.js', () => ({ logAuditEvent: mock.audit }))
vi.mock('../services/password-policy-service.js', () => ({
  getDefaultPolicy: async () => ({ historyCount: 5 }),
  validatePasswordPolicy: () => [],
  checkPasswordHistory: async () => false,
  recordPasswordHistory: vi.fn(),
}))
vi.mock('../services/breach-check-service.js', () => ({
  checkBreachedPassword: async () => 0,
}))
vi.mock('../services/password-service.js', () => ({
  hashPassword: async () => 'fake-password-hash',
  verifyPassword: async () => true,
}))
vi.mock('../services/recovery-delivery.js', () => ({
  recoveryOutbox: mock.outbox,
  deliverPasswordRecovery: mock.deliver,
}))
const { authRouter } = await import('./auth.js')
const app = new Hono().route('/auth', authRouter).onError(errorHandler)
const post = (path: string, body: object) =>
  app.request('/auth' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
it('browser self-profile exposes effective resource grants rather than underlying administrator roles', async () => {
  mock.user.findUnique.mockResolvedValue({
    id: 'fake-user',
    username: 'admin',
    displayName: 'Synthetic reader',
    roles: [{ role: { name: 'admin', permissions: '["*"]' } }],
    email: 'alice@example.com',
  })
  const response = await app.request('/auth/me')
  expect(response.status).toBe(200)
  expect(await response.json()).toEqual({
    user: {
      id: 'fake-user',
      username: 'admin',
      displayName: 'Synthetic reader',
      roles: ['reader'],
      permissions: ['iam:users:read'],
    },
  })
})
beforeEach(() => {
  vi.clearAllMocks()
  mock.deliver.mockResolvedValue(undefined)
  mock.claimed = false
  mock.outbox.mockResolvedValue('/opt/private/recovery')
  mock.passwordResetToken.findFirst.mockResolvedValue({
    id: 'fake-recovery-record',
    userId: 'fake-user',
    user: { email: 'alice@example.com' },
  })
  mock.passwordResetToken.updateMany.mockImplementation(async () => {
    if (mock.claimed) return { count: 0 }
    mock.claimed = true
    return { count: 1 }
  })
})
it('concurrent use of a reset token changes the password once and revokes every prior credential', async () => {
  const responses = await Promise.all([
    post('/reset-password', {
      token: 'fake-one-use-token',
      newPassword: 'obviously-fake-password',
    }),
    post('/reset-password', {
      token: 'fake-one-use-token',
      newPassword: 'another-fake-password',
    }),
  ])
  expect(responses.map((r) => r.status).sort()).toEqual([200, 400])
  expect(mock.user.update).toHaveBeenCalledOnce()
  expect(mock.session.updateMany).toHaveBeenCalledOnce()
  expect(mock.refreshToken.deleteMany).toHaveBeenCalledOnce()
  expect(mock.authorizationCode.deleteMany).toHaveBeenCalledOnce()
})
it('missing delivery configuration fails identically before account lookup', async () => {
  mock.outbox.mockRejectedValue(Error('not configured'))
  expect(
    (await post('/forgot-password', { email: 'alice@example.com' })).status,
  ).toBe(503)
  expect(mock.user.findUnique).not.toHaveBeenCalled()
  expect(mock.deliver).not.toHaveBeenCalled()
})
it('delivery failure hides account existence and invalidates the undelivered token', async () => {
  mock.user.findUnique
    .mockResolvedValueOnce({
      id: 'fake-user',
      email: 'alice@example.com',
      active: true,
    })
    .mockResolvedValueOnce(null)
  mock.deliver.mockRejectedValueOnce(Error('private delivery failure'))
  const known = await post('/forgot-password', { email: 'alice@example.com' }),
    unknown = await post('/forgot-password', { email: 'unknown@example.com' })
  expect(known.status).toBe(200)
  expect(await known.json()).toEqual(await unknown.json())
  expect(mock.passwordResetToken.updateMany).toHaveBeenLastCalledWith({
    where: { tokenHash: expect.any(String), usedAt: null },
    data: { usedAt: expect.any(Date) },
  })
  expect(mock.audit).toHaveBeenLastCalledWith(
    expect.objectContaining({ outcome: 'FAILURE' }),
  )
})
it('existing and unknown addresses receive the same public response without a recovery token', async () => {
  mock.user.findUnique
    .mockResolvedValueOnce({
      id: 'fake-user',
      email: 'alice@example.com',
      active: true,
    })
    .mockResolvedValueOnce(null)
  const known = await post('/forgot-password', { email: 'alice@example.com' }),
    unknown = await post('/forgot-password', { email: 'unknown@example.com' })
  expect(known.status).toBe(200)
  expect(await known.json()).toEqual(await unknown.json())
  expect(mock.deliver).toHaveBeenCalledOnce()
  expect(JSON.stringify(mock.audit.mock.calls)).not.toContain(
    mock.deliver.mock.calls[0]?.[2],
  )
})

it('replaying a used MFA challenge never consumes another recovery code', async () => {
  mock.user.findUnique.mockResolvedValue({
    id: 'fake-user',
    active: true,
    mfaEnabled: true,
    mfaSecret: null,
    mfaBackupCodes: '["fake-hash"]',
    roles: [],
    failedAttempts: 0,
  })
  mock.consumeChallenge.mockRejectedValueOnce(
    new ApiError(401, 'INVALID_MFA_TOKEN', 'Challenge already used'),
  )
  const response = await post('/mfa/challenge', {
    mfaToken: 'fake-used-challenge',
    code: 'fake-code',
  })
  expect(response.status).toBe(401)
  expect(mock.user.updateMany).not.toHaveBeenCalled()
})
