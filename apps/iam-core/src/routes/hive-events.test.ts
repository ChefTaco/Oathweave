/**
 * The session revocation feed (`GET /api/v1/hive/events`) against the real server: every way a
 * session ends records a HiveEvent v1 that names the session (`sid`) and the user (`sub`) and
 * nothing secret, served oldest first in cursor pages to callers that validate tokens.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { validateHiveEvent, type HiveEvent } from '@hivemagnus/hive-common/contracts'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const { startRealApp } = await import('../test-support/real-app.js')
const { resetFakeRedis } = await import('../test-support/fake-redis.js')
const harness = await startRealApp()
// After the harness: the module reads the database configuration when it loads.
const { pruneRevocationEvents, REVOCATION_EVENT_RETENTION_MS } = await import('../services/revocation-events.js')

const ADMIN_PERMISSIONS = ['iam:users:read', 'iam:users:write', 'iam:users:delete', 'iam:sessions:revoke']
interface Pair { accessToken: string; refreshToken: string; sessionId: string }
interface FeedPage { data: HiveEvent[]; nextCursor: string | null }
let admin: Pair

const json = (token: string, method: string, body?: unknown): RequestInit => ({
  method,
  headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
  ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
})
const feed = (token: string, query = '') => harness.request(`/api/v1/hive/events${query}`, { headers: { authorization: `Bearer ${token}` } })

/** Every event in the feed, read page by page with a small page size. */
async function readAll(token = admin.accessToken): Promise<HiveEvent[]> {
  const events: HiveEvent[] = []
  let cursor: string | null = null
  for (let pages = 0; pages < 100; pages++) {
    const response = await feed(token, `?limit=2${cursor ? `&after=${cursor}` : ''}`)
    expect(response.status).toBe(200)
    const page = (await response.json()) as FeedPage
    events.push(...page.data)
    if (page.nextCursor === null) return events
    cursor = page.nextCursor
  }
  throw new Error('feed did not end')
}
const sinceStart = async (start: number) => (await readAll()).slice(start)
const refresh = (refreshToken: string) =>
  harness.request('/api/v1/auth/refresh', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ refreshToken }) })
const sessionLive = async (sessionId: string) =>
  (await harness.prisma.session.findUniqueOrThrow({ where: { id: sessionId } })).revokedAt === null

beforeAll(async () => {
  await harness.createUser({ username: 'feed-admin', password: 'feed-admin-fixture', roles: [{ name: 'FEED_ADMIN', permissions: ADMIN_PERMISSIONS }] })
  await harness.createUser({ username: 'feed-service', password: 'feed-service-fixture', roles: [{ name: 'FEED_SERVICE', permissions: ['iam:tokens:introspect'] }] })
  await harness.createUser({ username: 'feed-viewer', password: 'feed-viewer-fixture', roles: [{ name: 'FEED_VIEWER', permissions: ['iam:users:read'] }] })
  admin = await harness.login('feed-admin', 'feed-admin-fixture')
})
beforeEach(() => resetFakeRedis())

describe('session revocation events', () => {
  it('are valid HiveEvent v1 that carry the session and user, never a credential', async () => {
    const { id } = await harness.createUser({ username: 'ana', password: 'ana-fixture-password' })
    const start = (await readAll()).length
    const login = await harness.login('ana', 'ana-fixture-password')
    expect((await harness.request('/api/v1/auth/logout', json(login.accessToken, 'POST'))).status).toBe(200)

    const events = await sinceStart(start)
    expect(events).toHaveLength(1)
    const [event] = events
    expect(validateHiveEvent(event, { strict: true })).toMatchObject({ ok: true })
    expect(event).toMatchObject({
      product: 'oathweave',
      type: 'session.revoked',
      severity: 'info',
      subject: { actorId: id },
      sourceRef: `session:${login.sessionId}`,
      link: { product: 'oathweave', path: '/?page=iam-users' },
    })
    expect(event!.summary).toContain('signed out')
    const text = JSON.stringify(events)
    for (const secret of [login.accessToken, login.refreshToken, 'ana-fixture-password']) expect(text).not.toContain(secret)
  })

  it('record administrator revocation, refresh-token reuse and a password change', async () => {
    const { id } = await harness.createUser({ username: 'ben', password: 'ben-fixture-password' })
    const start = (await readAll()).length
    const revoked = await harness.login('ben', 'ben-fixture-password')
    expect((await harness.request(`/api/v1/sessions/${revoked.sessionId}`, json(admin.accessToken, 'DELETE'))).status).toBe(200)

    const replayed = await harness.login('ben', 'ben-fixture-password')
    const successor = (await (await refresh(replayed.refreshToken)).json()) as Pair
    expect((await refresh(successor.refreshToken)).status).toBe(200)
    expect((await refresh(replayed.refreshToken)).status).toBe(401)

    const current = await harness.login('ben', 'ben-fixture-password')
    const other = await harness.login('ben', 'ben-fixture-password')
    const changed = await harness.request('/api/v1/auth/password', json(current.accessToken, 'POST', { currentPassword: 'ben-fixture-password', newPassword: 'Ben-new-fixture-pass-1!' }))
    expect(changed.status).toBe(200)
    expect(await sessionLive(current.sessionId)).toBe(true)

    const events = await sinceStart(start)
    expect(events.map(event => [event.type, event.sourceRef, event.severity])).toEqual([
      ['session.revoked', `session:${revoked.sessionId}`, 'info'],
      ['session.revoked', `session:${replayed.sessionId}`, 'warning'],
      ['session.revoked', `session:${other.sessionId}`, 'info'],
    ])
    expect(events.every(event => event.subject?.actorId === id)).toBe(true)
    expect(events.map(event => event.summary)).toEqual([
      expect.stringContaining('administrator'),
      expect.stringContaining('refresh token was reused'),
      expect.stringContaining('password change'),
    ])
  })

  it('end every session of a deactivated user and record the user-wide revocation', async () => {
    const { id } = await harness.createUser({ username: 'cy', password: 'cy-fixture-password' })
    const first = await harness.login('cy', 'cy-fixture-password')
    const second = await harness.login('cy', 'cy-fixture-password')
    const start = (await readAll()).length
    expect((await harness.request(`/api/v1/users/${id}`, json(admin.accessToken, 'PATCH', { active: false }))).status).toBe(200)

    expect(await sessionLive(first.sessionId)).toBe(false)
    expect(await sessionLive(second.sessionId)).toBe(false)
    const events = await sinceStart(start)
    expect(events.map(event => [event.type, event.sourceRef])).toEqual([
      ['session.revoked', `session:${first.sessionId}`],
      ['session.revoked', `session:${second.sessionId}`],
      ['user.sessions_revoked', `user:${id}`],
    ])
    expect(events[2]).toMatchObject({ subject: { actorId: id }, title: 'All sessions of a user revoked' })
    expect(events[2]!.summary).toContain('deactivated')

    // Reactivation does not bring an old session back.
    expect((await harness.request(`/api/v1/users/${id}`, json(admin.accessToken, 'PATCH', { active: true }))).status).toBe(200)
    expect(await sessionLive(first.sessionId)).toBe(false)
    expect(await sinceStart(start + 3)).toEqual([])
  })

  it('outlive a deleted user', async () => {
    const { id } = await harness.createUser({ username: 'dee', password: 'dee-fixture-password' })
    const login = await harness.login('dee', 'dee-fixture-password')
    const start = (await readAll()).length
    expect((await harness.request(`/api/v1/users/${id}`, json(admin.accessToken, 'DELETE'))).status).toBe(200)
    expect(await harness.prisma.session.findUnique({ where: { id: login.sessionId } })).toBeNull()
    expect((await sinceStart(start)).map(event => [event.type, event.sourceRef])).toEqual([
      ['session.revoked', `session:${login.sessionId}`],
      ['user.sessions_revoked', `user:${id}`],
    ])
  })

  it('record a password reset, in the transaction that ends the sessions', async () => {
    const { id } = await harness.createUser({ username: 'eli', password: 'eli-fixture-password' })
    const login = await harness.login('eli', 'eli-fixture-password')
    const { sha256Hex } = await import('@hivemagnus/hive-common/secrets')
    await harness.prisma.passwordResetToken.create({ data: { userId: id, tokenHash: sha256Hex('eli-fixture-reset-token'), expiresAt: new Date(Date.now() + 600_000) } })
    const start = (await readAll()).length
    const reset = await harness.request('/api/v1/auth/reset-password', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'eli-fixture-reset-token', newPassword: 'Eli-new-fixture-pass-1!' }),
    })
    expect(reset.status).toBe(200)
    const events = await sinceStart(start)
    expect(events.map(event => [event.type, event.sourceRef])).toEqual([
      ['session.revoked', `session:${login.sessionId}`],
      ['user.sessions_revoked', `user:${id}`],
    ])
    expect(JSON.stringify(events)).not.toContain('eli-fixture-reset-token')
  })

  it('record a revocation once, however often the session is revoked', async () => {
    await harness.createUser({ username: 'fay', password: 'fay-fixture-password' })
    const login = await harness.login('fay', 'fay-fixture-password')
    const start = (await readAll()).length
    await Promise.all([1, 2, 3].map(() => harness.request(`/api/v1/sessions/${login.sessionId}`, json(admin.accessToken, 'DELETE'))))
    expect(await sinceStart(start)).toHaveLength(1)
  })
})

describe('GET /api/v1/hive/events', () => {
  it('needs a token that may validate tokens or revoke sessions', async () => {
    expect((await harness.request('/api/v1/hive/events')).status).toBe(401)
    const viewer = await harness.login('feed-viewer', 'feed-viewer-fixture')
    expect((await feed(viewer.accessToken)).status).toBe(403)
    const service = await harness.login('feed-service', 'feed-service-fixture')
    const response = await feed(service.accessToken)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  it('pages oldest first with opaque cursors and refuses a cursor it did not issue', async () => {
    const all = await readAll()
    expect(all.length).toBeGreaterThan(3)
    expect(new Set(all.map(event => event.id)).size).toBe(all.length)
    const first = (await (await feed(admin.accessToken, '?limit=3')).json()) as FeedPage
    expect(first.data).toEqual(all.slice(0, 3))
    const second = (await (await feed(admin.accessToken, `?limit=3&after=${first.nextCursor}`)).json()) as FeedPage
    expect(second.data).toEqual(all.slice(3, 6))

    for (const query of ['?after=not-a-cursor', '?after=eyJ0IjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJpIjoieCJ9', '?limit=0', '?limit=abc']) {
      const response = await feed(admin.accessToken, query)
      expect(response.status).toBe(400)
    }
  })

  it('serves and keeps events for seven days only', async () => {
    const old = await harness.prisma.revocationEvent.create({
      data: { type: 'session.revoked', userId: 'retired-user', sessionId: 'retired-session', reason: 'admin', occurredAt: new Date(Date.now() - REVOCATION_EVENT_RETENTION_MS - 60_000) },
    })
    expect((await readAll()).some(event => event.sourceRef === 'session:retired-session')).toBe(false)
    expect(await pruneRevocationEvents()).toBeGreaterThanOrEqual(1)
    expect(await harness.prisma.revocationEvent.findUnique({ where: { seq: old.seq } })).toBeNull()
  })
})
