/**
 * The refresh-token retry window against the real server: a consumed refresh token sent again
 * within a few seconds (a lost response, two requests racing) gets the successor its rotation
 * already issued; outside the window, or once the successor has been used, reuse is a replay and
 * revokes the session.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const { startRealApp } = await import('../test-support/real-app.js')
const { resetFakeRedis, auditEvents } = await import('../test-support/fake-redis.js')
const harness = await startRealApp()

interface Pair { accessToken: string; refreshToken: string; sessionId: string }
const refresh = (refreshToken: string) =>
  harness.request('/api/v1/auth/refresh', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ refreshToken }),
  })
const sessionLive = async (sessionId: string) =>
  (await harness.prisma.session.findUniqueOrThrow({ where: { id: sessionId } })).revokedAt === null

beforeAll(async () => {
  await harness.createUser({ username: 'kim', password: 'kim-fixture-password' })
})
beforeEach(() => resetFakeRedis())
afterEach(() => vi.useRealTimers())

describe('refresh token reuse', () => {
  it('answers a retry inside the window with the same successor and keeps the session', async () => {
    const login: Pair = await harness.login('kim', 'kim-fixture-password')
    const first = await refresh(login.refreshToken)
    expect(first.status).toBe(200)
    const successor = (await first.json()) as Pair

    const retry = await refresh(login.refreshToken)
    expect(retry.status).toBe(200)
    expect(await retry.json()).toMatchObject({ accessToken: successor.accessToken, refreshToken: successor.refreshToken })
    expect(await sessionLive(login.sessionId)).toBe(true)
    expect(auditEvents.map((event) => event.eventType)).toContain('token.refresh_retry')

    // The successor still rotates normally.
    expect((await refresh(successor.refreshToken)).status).toBe(200)
  })

  it('gives racing refreshes of one token the same successor', async () => {
    const login: Pair = await harness.login('kim', 'kim-fixture-password')
    const answers = await Promise.all([refresh(login.refreshToken), refresh(login.refreshToken)])
    expect(answers.map((answer) => answer.status)).toEqual([200, 200])
    const [a, b] = (await Promise.all(answers.map((answer) => answer.json()))) as Pair[]
    expect(a!.refreshToken).toBe(b!.refreshToken)
    expect(await harness.prisma.refreshToken.count({ where: { sessionId: login.sessionId, revokedAt: null } })).toBe(1)
    expect(await sessionLive(login.sessionId)).toBe(true)
  })

  it('treats reuse after the successor was used as a replay', async () => {
    const login: Pair = await harness.login('kim', 'kim-fixture-password')
    const successor = (await (await refresh(login.refreshToken)).json()) as Pair
    expect((await refresh(successor.refreshToken)).status).toBe(200)

    expect((await refresh(login.refreshToken)).status).toBe(401)
    expect(await sessionLive(login.sessionId)).toBe(false)
  })

  it('treats reuse after the window as a replay', async () => {
    const login: Pair = await harness.login('kim', 'kim-fixture-password')
    expect((await refresh(login.refreshToken)).status).toBe(200)
    // Age the rotation past the window (the stored entry would also have expired by then).
    await harness.prisma.refreshToken.updateMany({ where: { sessionId: login.sessionId, revokedAt: { not: null } }, data: { revokedAt: new Date(Date.now() - 11_000) } })
    resetFakeRedis()

    expect((await refresh(login.refreshToken)).status).toBe(401)
    expect(await sessionLive(login.sessionId)).toBe(false)
  })

  it('treats reuse of a revoked token as a replay even inside the window', async () => {
    const login: Pair = await harness.login('kim', 'kim-fixture-password')
    await harness.prisma.refreshToken.updateMany({ where: { sessionId: login.sessionId }, data: { revokedAt: new Date() } })
    expect((await refresh(login.refreshToken)).status).toBe(401)
    expect(await sessionLive(login.sessionId)).toBe(false)
  })
})
