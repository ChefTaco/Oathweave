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
  keys: [] as string[],
}))
vi.mock('../config/env.js', () => ({ env: state.env }))
vi.mock('../queue/audit-queue.js', () => ({
  redisConnection: {
    pipeline: () => ({
      zremrangebyscore: () => undefined,
      zadd: (key: string) => { state.keys.push(key) },
      zcard: () => undefined,
      pexpire: () => undefined,
      exec: async () => [null, null, [null, ++state.count], null],
    }),
  },
}))
vi.mock('../utils/ip.js', () => ({ getClientIp: () => '203.0.113.7' }))

const { rateLimitMiddleware, redisSlidingWindowStore } = await import('./rate-limit.js')

function limited(opts: Parameters<typeof rateLimitMiddleware>[0]) {
  return new Hono()
    .use(rateLimitMiddleware(opts))
    .post('/', (c) => c.json({ ok: true }))
}
const attempt = async (app: Hono) => (await app.request('/', { method: 'POST' })).status

beforeEach(() => {
  state.env.RELAX_AUTH_LIMITS = false
  state.count = 0
  state.keys = []
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

describe('rate limit keys and responses', () => {
  it('keys every limiter by Redis prefix, limiter prefix and client address', async () => {
    await attempt(limited({ keyPrefix: 'rl:login', authAttempt: true }))
    await attempt(limited({}))
    expect(state.keys).toEqual(['fixture:rl:login:203.0.113.7', 'fixture:rl:203.0.113.7'])
  })

  it('keeps the RATE_LIMITED body and a whole-window Retry-After, not the Hive envelope', async () => {
    const app = limited({ keyPrefix: 'rl:token', max: 300, windowMs: 60_000 })
    state.count = 300
    const response = await app.request('/', { method: 'POST' })
    expect(response.status).toBe(429)
    expect(response.headers.get('Retry-After')).toBe('60')
    expect(await response.json()).toEqual({ error: 'RATE_LIMITED', message: 'Too many requests. Please try again later.' })
  })
})

describe('redisSlidingWindowStore', () => {
  function fakeRedis() {
    const sets = new Map<string, Array<{ score: number; member: string }>>()
    const calls: string[] = []
    return {
      calls,
      redis: {
        pipeline() {
          const ops: Array<() => unknown> = []
          return {
            zremrangebyscore: (key: string, _min: string, max: number) => { ops.push(() => { sets.set(key, (sets.get(key) ?? []).filter((e) => e.score > max)); return 0 }) },
            zadd: (key: string, score: number, member: string) => { ops.push(() => { sets.set(key, [...(sets.get(key) ?? []), { score, member }]); return 1 }) },
            zcard: (key: string) => { ops.push(() => (sets.get(key) ?? []).length) },
            pexpire: (key: string, ms: number) => { ops.push(() => { calls.push(`pexpire ${key} ${ms}`); return 1 }) },
            exec: async () => ops.map((op) => [null, op()] as [null, unknown]),
          }
        },
      },
    }
  }

  it('counts refused attempts, so retrying inside the window stays refused', async () => {
    let now = 1_000_000
    const { redis, calls } = fakeRedis()
    const store = redisSlidingWindowStore({ windowMs: 60_000, max: 2, now: () => now }, redis)
    expect((await store.consume('k')).allowed).toBe(true)
    expect((await store.consume('k')).allowed).toBe(true)
    now += 30_000
    const refused = await store.consume('k')
    expect(refused).toMatchObject({ allowed: false, limit: 2, remaining: 0, retryAfterMs: 60_000 })
    expect((await store.consume('k')).allowed).toBe(false)
    // The two allowed attempts have left the window; the two refused ones have not.
    now += 31_000
    expect((await store.consume('k')).allowed).toBe(false)
    // Only the last refused attempt is still inside the window.
    now += 30_000
    expect(await store.consume('k')).toMatchObject({ allowed: true, remaining: 0 })
    expect(calls.at(-1)).toBe('pexpire k 60000')
  })

  it('keeps separate windows per key', async () => {
    const { redis } = fakeRedis()
    const store = redisSlidingWindowStore({ windowMs: 60_000, max: 1, now: () => 5 }, redis)
    expect((await store.consume('a')).allowed).toBe(true)
    expect((await store.consume('a')).allowed).toBe(false)
    expect((await store.consume('b')).allowed).toBe(true)
  })
})
