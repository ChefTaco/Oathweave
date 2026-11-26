import { TOTP, Secret } from 'otpauth'
import * as QRCode from 'qrcode'
import { nanoid } from 'nanoid'
import argon2 from 'argon2'
import { redisConnection } from '../queue/audit-queue.js'
import { env } from '../config/env.js'

const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
}

const ISSUER = 'Hive IAM'
const BACKUP_CODE_COUNT = 10
const BACKUP_CODE_LENGTH = 8

/**
 * Generate a TOTP secret for a user. Returns the base32 secret,
 * the otpauth:// URI, and a data-URL QR code image.
 */
export async function generateTotpSecret(
  email: string,
): Promise<{ secret: string; uri: string; qrDataUrl: string }> {
  const secret = new Secret({ size: 20 })

  const totp = new TOTP({
    issuer: ISSUER,
    label: email,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret,
  })

  const uri = totp.toString()
  const qrDataUrl = await QRCode.toDataURL(uri)

  return {
    secret: secret.base32,
    uri,
    qrDataUrl,
  }
}

const TOTP_PERIOD_SECONDS = 30

function totpFor(secret: string): TOTP {
  return new TOTP({
    issuer: ISSUER,
    algorithm: 'SHA1',
    digits: 6,
    period: TOTP_PERIOD_SECONDS,
    secret: Secret.fromBase32(secret),
  })
}

/** The time step a code matches (±1 period for clock skew), or null when it matches none. */
export function matchTotpStep(secret: string, code: string, now: number = Date.now()): number | null {
  // validate returns the time step difference, or null if invalid
  const delta = totpFor(secret).validate({ token: code, window: 1, timestamp: now })
  return delta === null ? null : Math.floor(now / 1000 / TOTP_PERIOD_SECONDS) + delta
}

/**
 * Verify a 6-digit TOTP code against the stored base32 secret.
 * Allows ±1 time window tolerance for clock skew. Does not prevent replay: sign-in, step-up and
 * MFA changes use `consumeTotpCode`.
 */
export function verifyTotpCode(secret: string, code: string): boolean {
  return matchTotpStep(secret, code) !== null
}

// Accept a step only when it is later than the last step accepted for this user.
const CLAIM_TOTP_STEP = `
local last = tonumber(redis.call('GET', KEYS[1]) or '-1')
local step = tonumber(ARGV[1])
if step <= last then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1
`

/**
 * Verify a TOTP code and claim its time step, so that a code (or any code from an earlier
 * step) cannot be accepted twice for the same user (RFC 6238 §5.2).
 */
export async function consumeTotpCode(userId: string, secret: string, code: string): Promise<boolean> {
  const step = matchTotpStep(secret, code)
  if (step === null) return false
  // Remember the step for longer than any code that the ±1 window could still accept.
  const retainMs = TOTP_PERIOD_SECONDS * 4 * 1000
  const claimed = await redisConnection.eval(
    CLAIM_TOTP_STEP,
    1,
    `${env.REDIS_PREFIX}:totp-step:${userId}`,
    String(step),
    String(retainMs),
  )
  return claimed === 1
}

/**
 * Generate single-use backup codes.
 * Returns both the plaintext codes (shown once to user) and their Argon2id hashes (stored in DB).
 */
export async function generateBackupCodes(): Promise<{
  plaintextCodes: string[]
  hashedCodes: string[]
}> {
  const plaintextCodes: string[] = []
  const hashedCodes: string[] = []

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = nanoid(BACKUP_CODE_LENGTH)
    plaintextCodes.push(code)
    const hash = await argon2.hash(code, ARGON2_OPTIONS)
    hashedCodes.push(hash)
  }

  return { plaintextCodes, hashedCodes }
}

/**
 * Verify a backup code against stored hashes.
 * Returns the index of the matched code, or -1 if none match.
 */
export async function verifyBackupCode(
  code: string,
  hashedCodes: string[],
): Promise<number> {
  for (let i = 0; i < hashedCodes.length; i++) {
    const hash = hashedCodes[i]!
    if (hash === '') continue // Already used
    try {
      const match = await argon2.verify(hash, code, ARGON2_OPTIONS)
      if (match) return i
    } catch {
      // Invalid hash format — skip
    }
  }
  return -1
}
