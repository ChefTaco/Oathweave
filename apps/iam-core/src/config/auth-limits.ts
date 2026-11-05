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
 * Whether an account lock currently denies access. Failed credentials lock an
 * account for at most one rate-limit window, so relaxed mode ignores only those
 * locks. Longer locks are administrator actions and are always enforced. The
 * stored lock is left untouched, so normal enforcement resumes with the flag off.
 */
export function accountLockActive(
  lockedUntil: Date | null | undefined,
  now: Date = new Date(),
): boolean {
  if (!lockedUntil || lockedUntil <= now) return false
  if (!authLimitsRelaxed()) return true
  return lockedUntil.getTime() - now.getTime() > env.RATE_LIMIT_WINDOW_MS
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
