import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Secret, TOTP } from 'otpauth'

// Emulates the claim script: accept a step only when it is later than the stored one.
const redis = vi.hoisted(() => ({ steps: new Map<string, number>() }))
vi.mock('../config/env.js', () => ({ env: { REDIS_PREFIX: 'fixture' } }))
vi.mock('../queue/audit-queue.js', () => ({
  redisConnection: {
    eval: vi.fn(async (_script: string, _keys: number, key: string, step: string) => {
      const last = redis.steps.get(key) ?? -1
      if (Number(step) <= last) return 0
      redis.steps.set(key, Number(step))
      return 1
    }),
  },
}))

const { consumeTotpCode, matchTotpStep, verifyTotpCode } = await import('./mfa-service.js')

const secret = new Secret({ size: 20 }).base32
const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(secret) })
const codeAt = (ms: number) => totp.generate({ timestamp: ms })
const start = Date.UTC(2026, 0, 1, 12, 0, 0)

beforeEach(() => {
  redis.steps.clear()
  vi.useFakeTimers()
  vi.setSystemTime(start)
})
afterEach(() => vi.useRealTimers())

describe('TOTP replay prevention', () => {
  it('accepts a code once per user', async () => {
    const code = codeAt(start)
    expect(verifyTotpCode(secret, code)).toBe(true)
    expect(await consumeTotpCode('fixture-user', secret, code)).toBe(true)
    expect(await consumeTotpCode('fixture-user', secret, code)).toBe(false)
    // Another account's claim is independent.
    expect(await consumeTotpCode('other-user', secret, code)).toBe(true)
  })

  it('refuses a code from an earlier step once a later one was accepted', async () => {
    const earlier = codeAt(start - 30_000)
    const current = codeAt(start)
    expect(matchTotpStep(secret, earlier)).toBe(matchTotpStep(secret, current)! - 1)
    expect(await consumeTotpCode('fixture-user', secret, current)).toBe(true)
    expect(await consumeTotpCode('fixture-user', secret, earlier)).toBe(false)
  })

  it('accepts the next step after one was used', async () => {
    expect(await consumeTotpCode('fixture-user', secret, codeAt(start))).toBe(true)
    vi.setSystemTime(start + 30_000)
    expect(await consumeTotpCode('fixture-user', secret, codeAt(start + 30_000))).toBe(true)
  })

  it('rejects a wrong code without claiming a step', async () => {
    const wrong = codeAt(start + 10 * 60_000)
    expect(await consumeTotpCode('fixture-user', secret, wrong)).toBe(false)
    expect(redis.steps.size).toBe(0)
  })
})
