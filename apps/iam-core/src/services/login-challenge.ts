import { createHash } from 'node:crypto'
import { jwtVerify } from 'jose'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { accountLockActive } from '../config/auth-limits.js'
import { getPublicKey } from '../utils/keys.js'
import { redisConnection } from '../queue/audit-queue.js'
import { ApiError } from '../types/index.js'

export async function loginChallengeUser(token: string): Promise<string> {
  try {
    const { payload } = await jwtVerify(token, await getPublicKey(), {
      issuer: env.JWT_ISSUER,
      algorithms: ['RS256'],
      requiredClaims: ['sub', 'iat', 'exp', 'jti'],
    })
    if (
      payload.purpose !== 'mfa_challenge' ||
      typeof payload.sub !== 'string' ||
      typeof payload.passwordVersion !== 'number'
    )
      throw new Error('Invalid challenge')
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        active: true,
        mfaEnabled: true,
        lockedUntil: true,
        passwordChangedAt: true,
      },
    })
    if (
      !user?.active ||
      !user.mfaEnabled ||
      accountLockActive(user.lockedUntil) ||
      (user.passwordChangedAt?.getTime() ?? 0) !== payload.passwordVersion
    )
      throw new Error('Identity changed')
    return payload.sub
  } catch {
    throw new ApiError(
      401,
      'INVALID_MFA_TOKEN',
      'MFA challenge expired or identity changed; start sign-in again',
    )
  }
}

/** Consume only after a second factor is verified. Shared across TOTP/passkeys. */
export async function consumeLoginChallenge(token: string): Promise<void> {
  const key =
    env.REDIS_PREFIX +
    ':mfa:used:' +
    createHash('sha256').update(token).digest('hex')
  let timer: NodeJS.Timeout | undefined
  try {
    const result = await Promise.race([
      redisConnection.set(key, 'used', 'EX', 300, 'NX'),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error('Challenge store unavailable')),
          5000,
        )
      }),
    ])
    if (result !== 'OK')
      throw new ApiError(
        401,
        'INVALID_MFA_TOKEN',
        'MFA challenge has already been used; start sign-in again',
      )
  } finally {
    if (timer) clearTimeout(timer)
  }
}
