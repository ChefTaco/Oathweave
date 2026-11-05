import { beforeEach, describe, expect, it, vi } from 'vitest'

const env = vi.hoisted(() => ({
  RELAX_AUTH_LIMITS: false,
  RATE_LIMIT_WINDOW_MS: 900_000,
}))
vi.mock('./env.js', () => ({ env }))

const {
  accountLockActive,
  authAttemptCeiling,
  authLimitsRelaxed,
  relaxedAuthLimitsWarning,
  RELAXED_AUTH_ATTEMPT_CEILING,
} = await import('./auth-limits.js')
const { envSchema } = await import('./env-schema.js')

const now = new Date('2026-01-01T00:00:00Z')
const inMinutes = (minutes: number) =>
  new Date(now.getTime() + minutes * 60_000)

beforeEach(() => {
  env.RELAX_AUTH_LIMITS = false
})

describe('default authentication limits', () => {
  it('keep every configured ceiling and enforce every unexpired lock', () => {
    expect(authLimitsRelaxed()).toBe(false)
    expect(authAttemptCeiling(5)).toBe(5)
    expect(accountLockActive(inMinutes(1), now)).toBe(true)
    expect(accountLockActive(inMinutes(60 * 24 * 365), now)).toBe(true)
    expect(accountLockActive(inMinutes(-1), now)).toBe(false)
    expect(accountLockActive(null, now)).toBe(false)
  })
})

describe('relaxed authentication limits', () => {
  beforeEach(() => {
    env.RELAX_AUTH_LIMITS = true
  })

  it('raise ceilings without ever lowering a larger configured limit', () => {
    expect(authAttemptCeiling(5)).toBe(RELAXED_AUTH_ATTEMPT_CEILING)
    expect(authAttemptCeiling(20_000)).toBe(20_000)
    expect(RELAXED_AUTH_ATTEMPT_CEILING).toBe(10_000)
  })

  it('ignore failure locks but still enforce administrator locks', () => {
    expect(accountLockActive(inMinutes(15), now)).toBe(false)
    expect(accountLockActive(inMinutes(60 * 24 * 365), now)).toBe(true)
  })

  it('name the mode in the startup warning', () => {
    expect(relaxedAuthLimitsWarning()).toContain('RELAX_AUTH_LIMITS=true')
    expect(relaxedAuthLimitsWarning()).toContain('10000')
  })
})

describe('RELAX_AUTH_LIMITS parsing', () => {
  const required = {
    DATABASE_URL: 'file:/tmp/example.db',
    JWT_PRIVATE_KEY_PATH: '/tmp/private.pem',
    JWT_PUBLIC_KEY_PATH: '/tmp/public.pem',
    COOKIE_SECRET: 'x'.repeat(32),
    IAM_AGENT_SECRET: 'x'.repeat(16),
  }
  const parse = (value?: string) =>
    envSchema.safeParse({
      ...required,
      ...(value === undefined ? {} : { RELAX_AUTH_LIMITS: value }),
    })

  it('defaults off, and accepts only exact booleans so a typo fails closed', () => {
    expect(parse().data?.RELAX_AUTH_LIMITS).toBe(false)
    expect(parse('false').data?.RELAX_AUTH_LIMITS).toBe(false)
    expect(parse('true').data?.RELAX_AUTH_LIMITS).toBe(true)
    expect(parse('yes').success).toBe(false)
    expect(parse('1').success).toBe(false)
  })
})
