import type { MiddlewareHandler } from 'hono'
import type { RateLimitResult, RateLimitStore } from '@hivemagnus/hive-common/rate-limit'
import { redisConnection } from '../queue/audit-queue.js'
import { env } from '../config/env.js'
import { authAttemptCeiling } from '../config/auth-limits.js'
import { getClientIp } from '../utils/ip.js'

/** The Redis commands the sliding window needs (ioredis pipeline). */
interface SlidingWindowRedis {
  pipeline(): {
    zremrangebyscore(key: string, min: string, max: number): unknown
    zadd(key: string, score: number, member: string): unknown
    zcard(key: string): unknown
    pexpire(key: string, ms: number): unknown
    exec(): Promise<Array<[Error | null, unknown]> | null>
  }
}

/**
 * A HiveCommon `RateLimitStore` over Oathweave's Redis sliding window: every request, refused ones
 * included, is recorded in a sorted set per key, and a request is refused while more than `max`
 * fall inside the last `windowMs`. Refused attempts count, so a client that keeps retrying stays
 * refused; the window lives in Redis, so it survives restarts and `scripts/reset-iam-locks.sh`
 * clears it (`<REDIS_PREFIX>:rl:*`). HiveCommon's in-memory token bucket has neither property.
 */
export function redisSlidingWindowStore(
  opts: { windowMs: number; max: number; now?: () => number },
  redis: SlidingWindowRedis = redisConnection as unknown as SlidingWindowRedis,
): RateLimitStore {
  return {
    async consume(key): Promise<RateLimitResult> {
      const now = opts.now ? opts.now() : Date.now()
      const pipe = redis.pipeline()
      pipe.zremrangebyscore(key, '-inf', now - opts.windowMs)
      pipe.zadd(key, now, `${now}-${Math.random()}`)
      pipe.zcard(key)
      pipe.pexpire(key, opts.windowMs)
      const results = await pipe.exec()
      const count = (results?.[2]?.[1] as number) ?? 0
      const allowed = count <= opts.max
      return {
        allowed,
        limit: opts.max,
        remaining: Math.max(0, opts.max - count),
        // The newest attempt leaves the window last, so a refusal lasts a whole window.
        retryAfterMs: allowed ? 0 : opts.windowMs,
        resetMs: opts.windowMs,
      }
    },
  }
}

/**
 * Sliding-window rate limiter backed by Redis.
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
  const store = redisSlidingWindowStore({ windowMs, max })

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
