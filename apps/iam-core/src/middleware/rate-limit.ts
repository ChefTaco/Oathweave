import type { MiddlewareHandler } from 'hono'
import { createRedisSlidingWindowStore, type SlidingWindowRedis } from '@hivemagnus/hive-common/rate-limit'
import { redisConnection } from '../queue/audit-queue.js'
import { env } from '../config/env.js'
import { authAttemptCeiling } from '../config/auth-limits.js'
import { getClientIp } from '../utils/ip.js'

/**
 * Sliding-window rate limiter backed by Redis: HiveCommon `createRedisSlidingWindowStore()`, one
 * sorted set per key. Every request, refused ones included, is recorded, so a client that keeps
 * retrying stays refused; a refusal's `Retry-After` is the whole window (the newest attempt leaves
 * it last). The window lives in Redis, so it survives restarts and `scripts/reset-iam-locks.sh`
 * clears it (`<REDIS_PREFIX>:rl:*`); each set keeps at most `max + 1` entries. A Redis command
 * error is thrown (a 500 from the error handler), never read as allowed.
 *
 * Keyed by client address (`getClientIp`: HiveCommon `resolveClientAddress()` over
 * `TRUSTED_PROXY_IPS`).
 *
 * `authAttempt` marks credential and second-factor checks, whose ceiling is
 * raised while RELAX_AUTH_LIMITS is on. Other limiters are never relaxed.
 *
 * The 429 body stays `{ error: 'RATE_LIMITED', message }`, the body clients and the OAuth endpoints
 * have always returned, rather than the Hive error envelope.
 */
export function rateLimitMiddleware(
  opts: {
    windowMs?: number
    max?: number
    keyPrefix?: string
    authAttempt?: boolean
  } = {},
): MiddlewareHandler {
  const windowMs = opts.windowMs ?? env.RATE_LIMIT_WINDOW_MS
  const configuredMax = opts.max ?? env.RATE_LIMIT_MAX_ATTEMPTS
  const max = opts.authAttempt ? authAttemptCeiling(configuredMax) : configuredMax
  const prefix = opts.keyPrefix ?? 'rl'
  const store = createRedisSlidingWindowStore({
    redis: () => redisConnection as unknown as SlidingWindowRedis,
    windowMs,
    max,
    retryAfter: 'window',
  })

  return async (c, next) => {
    const result = await store.consume(`${env.REDIS_PREFIX}:${prefix}:${getClientIp(c)}`)
    if (!result.allowed) {
      c.header('Retry-After', String(Math.ceil(result.retryAfterMs / 1000)))
      return c.json(
        { error: 'RATE_LIMITED', message: 'Too many requests. Please try again later.' },
        429,
      )
    }

    return next()
  }
}
