import argon2 from 'argon2'
import type { MiddlewareHandler } from 'hono'
import { redisConnection } from '../queue/audit-queue.js'
import { env } from '../config/env.js'
import { authAttemptCeiling } from '../config/auth-limits.js'
import { rateLimitMiddleware } from '../middleware/rate-limit.js'
import { ApiError } from '../types/index.js'

/**
 * Client-authentication throttle, shared by the token endpoint and the client-authenticated
 * token routes (introspection, revocation).
 *
 * Every failed client authentication (unknown or inactive client, missing or wrong secret) is
 * counted per source address and per source address and client. Once either count reaches its
 * ceiling inside the window, further attempts from that address are refused before any secret
 * is verified, so client secrets cannot be guessed online and the argon2 verification cannot be
 * driven as a CPU lever. Successful authentications are never counted, so healthy clients that
 * share an address with a misconfigured one keep working until the address itself is over its
 * ceiling.
 */

export const CLIENT_AUTH_FAILURE_WINDOW_MS = 300_000
/** Failed authentications allowed per window for one client from one address. */
export const CLIENT_AUTH_MAX_FAILURES_PER_CLIENT = 10
/** Failed authentications allowed per window from one address, across clients. */
export const CLIENT_AUTH_MAX_FAILURES_PER_ADDRESS = 30

/** Requests per minute and address on the token endpoint and the client-authenticated routes. */
export const CLIENT_ENDPOINT_MAX_REQUESTS_PER_MINUTE = 300

export function clientEndpointRateLimit(keyPrefix: string): MiddlewareHandler {
  return rateLimitMiddleware({
    keyPrefix,
    max: CLIENT_ENDPOINT_MAX_REQUESTS_PER_MINUTE,
    windowMs: 60_000,
    authAttempt: true,
  })
}

function failureKeys(ip: string, clientId: string | undefined): { address: string; client: string } {
  const base = `${env.REDIS_PREFIX}:rl:client-auth-fail`
  // The client id is caller-chosen; bound its length so it cannot grow a key without limit.
  const client = (clientId ?? '').slice(0, 200)
  return { address: `${base}:${ip}`, client: `${base}:${ip}:${client}` }
}

/** Refuses with 429 when this address (or this client from this address) failed too often. */
export async function assertClientAuthAllowed(ip: string, clientId: string | undefined): Promise<void> {
  const keys = failureKeys(ip, clientId)
  const windowStart = Date.now() - CLIENT_AUTH_FAILURE_WINDOW_MS
  const pipe = redisConnection.pipeline()
  pipe.zremrangebyscore(keys.address, '-inf', windowStart)
  pipe.zcard(keys.address)
  pipe.zremrangebyscore(keys.client, '-inf', windowStart)
  pipe.zcard(keys.client)
  const results = await pipe.exec()
  const addressFailures = (results?.[1]?.[1] as number) ?? 0
  const clientFailures = (results?.[3]?.[1] as number) ?? 0
  if (
    addressFailures >= authAttemptCeiling(CLIENT_AUTH_MAX_FAILURES_PER_ADDRESS) ||
    clientFailures >= authAttemptCeiling(CLIENT_AUTH_MAX_FAILURES_PER_CLIENT)
  ) {
    throw new ApiError(429, 'RATE_LIMITED', 'Too many failed client authentications. Please try again later.')
  }
}

export async function recordClientAuthFailure(ip: string, clientId: string | undefined): Promise<void> {
  const keys = failureKeys(ip, clientId)
  const now = Date.now()
  const member = `${now}-${Math.random()}`
  const pipe = redisConnection.pipeline()
  pipe.zadd(keys.address, now, member)
  pipe.pexpire(keys.address, CLIENT_AUTH_FAILURE_WINDOW_MS)
  pipe.zadd(keys.client, now, member)
  pipe.pexpire(keys.client, CLIENT_AUTH_FAILURE_WINDOW_MS)
  await pipe.exec()
}

/**
 * Verifies a presented client secret against its stored hash, counting a mismatch as a failed
 * client authentication. Callers run `assertClientAuthAllowed` first.
 */
export async function verifyClientSecret(
  ip: string,
  clientId: string,
  secretHash: string,
  presented: string,
): Promise<boolean> {
  const valid = await argon2.verify(secretHash, presented)
  if (!valid) await recordClientAuthFailure(ip, clientId)
  return valid
}
