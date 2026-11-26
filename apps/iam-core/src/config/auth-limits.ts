import { env } from './env.js'

/** Sign-in attempts allowed per window while RELAX_AUTH_LIMITS is on. */
export const RELAXED_AUTH_ATTEMPT_CEILING = 10_000

/** Opt-in testing mode. Runtime only: it never changes stored policy or accounts. */
export function authLimitsRelaxed(): boolean {
  return env.RELAX_AUTH_LIMITS === true
}

/** The configured ceiling, unless relaxed mode raises it. Relaxing never lowers a limit. */
export function authAttemptCeiling(configured: number): number {
  return authLimitsRelaxed()
    ? Math.max(configured, RELAXED_AUTH_ATTEMPT_CEILING)
    : configured
}

/**
 * The longest lock a failed sign-in can set: the password policy's `lockoutDurationMin` is at most
 * 1440 minutes (see schemas/password-policy.ts). Administrator locks last a year.
 */
export const MAX_FAILURE_LOCK_MS = 1440 * 60_000

/**
 * When the stored password policy locks an account after `attempts` consecutive failures, the
 * time the lock ends; otherwise undefined. Sign-in and the MFA challenge both use it, so the
 * policy's `lockoutAttempts` and `lockoutDurationMin` are what an administrator edits.
 */
export function lockoutAfterFailure(
  policy: { lockoutAttempts: number; lockoutDurationMin: number },
  attempts: number,
  now: Date = new Date(),
): Date | undefined {
  const threshold = Math.max(1, Math.trunc(policy.lockoutAttempts))
  if (attempts < threshold) return undefined
  const minutes = Math.min(Math.max(1, Math.trunc(policy.lockoutDurationMin)), MAX_FAILURE_LOCK_MS / 60_000)
  return new Date(now.getTime() + minutes * 60_000)
}

/**
 * Whether an account lock currently denies access. Failed credentials lock an
 * account for at most MAX_FAILURE_LOCK_MS (older releases used one rate-limit
 * window), so relaxed mode ignores only locks that short. Longer locks are
 * administrator actions and are always enforced. The stored lock is left
 * untouched, so normal enforcement resumes with the flag off.
 */
export function accountLockActive(
  lockedUntil: Date | null | undefined,
  now: Date = new Date(),
): boolean {
  if (!lockedUntil || lockedUntil <= now) return false
  if (!authLimitsRelaxed()) return true
  return lockedUntil.getTime() - now.getTime() > Math.max(env.RATE_LIMIT_WINDOW_MS, MAX_FAILURE_LOCK_MS)
}

export function relaxedAuthLimitsWarning(): string {
  const rule = '!'.repeat(78)
  return [
    rule,
    '!! WARNING: AUTHENTICATION LIMITS ARE RELAXED (--relax-auth-limits / RELAX_AUTH_LIMITS=true)',
    `!! Sign-in, MFA and step-up throttles allow ${RELAXED_AUTH_ATTEMPT_CEILING} attempts per window.`,
    '!! Failed passwords and MFA codes do not lock accounts. Administrator locks still apply.',
    '!! For testing only. Do not expose this instance to untrusted networks.',
    rule,
  ].join('\n')
}
