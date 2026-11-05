import { Hono } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  env: {
    RELAX_AUTH_LIMITS: false,
    RATE_LIMIT_WINDOW_MS: 900_000,
    RATE_LIMIT_MAX_ATTEMPTS: 5,
    REDIS_PREFIX: 'fixture',
  },
  count: 0,
}))
vi.mock('../config/env.js', () => ({ env: state.env }))
vi.mock('../queue/audit-queue.js', () => ({
  redisConnection: {
    pipeline: () => ({
      zremrangebyscore: () => undefined,
      zadd: () => undefined,
      zcard: () => undefined,
      pexpire: () => undefined,
      exec: async () => [null, null, [null, ++state.count], null],
    }),
  },
}))
vi.mock('../utils/ip.js', () => ({ getClientIp: () => '203.0.113.7' }))

const { rateLimitMiddleware } = await import('./rate-limit.js')

function limited(opts: Parameters<typeof rateLimitMiddleware>[0]) {
  return new Hono()
    .use(rateLimitMiddleware(opts))
    .post('/', (c) => c.json({ ok: true }))
}
const attempt = async (app: Hono) => (await app.request('/', { method: 'POST' })).status

beforeEach(() => {
  state.env.RELAX_AUTH_LIMITS = false
  state.count = 0
})

describe('rate limit ceilings', () => {
  it('blocks the sixth sign-in attempt by default', async () => {
    const app = limited({ keyPrefix: 'rl:login', authAttempt: true })
    for (let index = 1; index <= 5; index++) expect(await attempt(app)).toBe(200)
    const response = await app.request('/', { method: 'POST' })
    expect(response.status).toBe(429)
    expect(response.headers.get('Retry-After')).toBe('900')
  })

  it('allows 10000 sign-in attempts per window when relaxed and still throttles the next', async () => {
    state.env.RELAX_AUTH_LIMITS = true
    const app = limited({ keyPrefix: 'rl:login', authAttempt: true })
    expect(await attempt(app)).toBe(200)
    state.count = 9_999
    expect(await attempt(app)).toBe(200)
    expect(await attempt(app)).toBe(429)
  })

  it('raises an explicit authentication limit when relaxed', async () => {
    state.env.RELAX_AUTH_LIMITS = true
    const app = limited({ keyPrefix: 'rl:mfa', max: 5, windowMs: 300_000, authAttempt: true })
    state.count = 5
    expect(await attempt(app)).toBe(200)
  })

  it('never relaxes a limiter that is not an authentication attempt', async () => {
    state.env.RELAX_AUTH_LIMITS = true
    const app = limited({ keyPrefix: 'rl:forgot', max: 5, windowMs: 300_000 })
    state.count = 5
    expect(await attempt(app)).toBe(429)
  })
})
