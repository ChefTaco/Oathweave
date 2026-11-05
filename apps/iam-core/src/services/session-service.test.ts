import { beforeEach, expect, it, vi } from 'vitest'
interface Session {
  id: string
  userId: string
  ipAddress?: string
  userAgent?: string
  revokedAt: Date | null
  revokedBy?: string
  expiresAt: Date
}
const mock = vi.hoisted(() => ({
  sessions: [] as Session[],
  refresh: [] as { sessionId: string; revokedAt: Date | null }[],
  updated: vi.fn(),
  refreshUpdated: vi.fn(),
}))
vi.mock('../config/env.js', () => ({ env: { JWT_REFRESH_TTL: 3600 } }))
vi.mock('./session-risk-service.js', () => ({
  computeSessionRisk: async () => ({ score: 0.1, factors: ['shared_network'] }),
  deriveDeviceFingerprint: () => 'synthetic-shared-fingerprint',
}))
vi.mock('../db/client.js', () => ({ prisma: {
  session: {
    create: async ({ data }: { data: Omit<Session, 'revokedAt'> }) => {
      const session = { ...data, revokedAt: null }; mock.sessions.push(session); return session
    },
    findMany: async ({ where }: { where: { userId?: string; revokedAt?: null; expiresAt?: { gt: Date } } }) =>
      mock.sessions.filter(row => (!where.userId || row.userId === where.userId) &&
        (where.revokedAt !== null || row.revokedAt === null) &&
        (!where.expiresAt || row.expiresAt > where.expiresAt.gt)),
    update: mock.updated,
    updateMany: vi.fn(() => { throw Error('Unexpected bulk session mutation') }),
  },
  refreshToken: { updateMany: mock.refreshUpdated },
} }))
import { createSession, deduplicateSessions, listActiveSessions, revokeAllUserSessions, revokeSession } from './session-service.js'
beforeEach(() => {
  vi.clearAllMocks(); mock.sessions.length = 0; mock.refresh.length = 0
  mock.updated.mockImplementation(async ({ where, data }: { where: { id: string }; data: { revokedAt: Date; revokedBy?: string } }) => {
    const row = mock.sessions.find(session => session.id === where.id)
    if (!row) throw Error('Unknown synthetic session')
    Object.assign(row, data); return row
  })
  mock.refreshUpdated.mockImplementation(async ({ where, data }: { where: { sessionId: string }; data: { revokedAt: Date } }) => {
    for (const row of mock.refresh) if (row.sessionId === where.sessionId && row.revokedAt === null) row.revokedAt = data.revokedAt
  })
})
it('retains independent logins and refresh tokens with identical IP, browser and risk fingerprint', async () => {
  const first = await createSession('synthetic-user', '192.0.2.10', 'Synthetic browser')
  mock.refresh.push({ sessionId: first.sessionId, revokedAt: null })
  const second = await createSession('synthetic-user', '192.0.2.10', 'Synthetic browser')
  expect(second.sessionId).not.toBe(first.sessionId)
  expect((await listActiveSessions('synthetic-user')).map(row => row.id)).toEqual([first.sessionId, second.sessionId])
  expect(mock.refresh[0]?.revokedAt).toBeNull()
  expect(mock.updated).not.toHaveBeenCalled(); expect(mock.refreshUpdated).not.toHaveBeenCalled()
})
it('refuses heuristic cleanup without changing any session or refresh credential', async () => {
  await createSession('synthetic-user'); await createSession('synthetic-user')
  const before = JSON.stringify(mock.sessions)
  await expect(deduplicateSessions()).rejects.toMatchObject({ status: 409, code: 'EXPLICIT_SESSION_SELECTION_REQUIRED' })
  expect(JSON.stringify(mock.sessions)).toBe(before)
  expect(mock.refreshUpdated).not.toHaveBeenCalled()
})
it('explicit revocation invalidates only the selected session and its refresh credentials', async () => {
  const first = await createSession('synthetic-user', '192.0.2.10', 'Synthetic browser')
  const second = await createSession('synthetic-user', '192.0.2.10', 'Synthetic browser')
  mock.refresh.push({ sessionId: first.sessionId, revokedAt: null }, { sessionId: second.sessionId, revokedAt: null })
  await revokeSession(first.sessionId, 'synthetic-operator')
  expect(mock.sessions.find(row => row.id === first.sessionId)?.revokedBy).toBe('synthetic-operator')
  expect(mock.refresh.find(row => row.sessionId === first.sessionId)?.revokedAt).toBeInstanceOf(Date)
  expect(mock.refresh.find(row => row.sessionId === second.sessionId)?.revokedAt).toBeNull()
  expect((await listActiveSessions('synthetic-user')).map(row => row.id)).toEqual([second.sessionId])
})
it('explicit revoke-all remains confined to the selected user', async () => {
  await createSession('synthetic-user'); await createSession('synthetic-user')
  const other = await createSession('synthetic-other')
  await revokeAllUserSessions('synthetic-user', 'synthetic-operator')
  expect((await listActiveSessions()).map(row => row.id)).toEqual([other.sessionId])
})
