import type { MiddlewareHandler } from 'hono'
import { prisma } from '../db/client.js'
import { getClientIp } from '../utils/ip.js'
import { checkIpAllowlist } from '../utils/ip-allowlist.js'
import { ApiError } from '../types/index.js'
import {
  assertClientAuthAllowed,
  CLIENT_AUTH_FAILURE_WINDOW_MS,
  recordClientAuthFailure,
  verifyClientSecret,
} from '../services/client-auth-guard.js'

declare module 'hono' {
  interface ContextVariableMap {
    clientId: string
  }
}

/**
 * Validates x-client-id + x-client-secret headers.
 * Used for token introspection and other machine-to-machine routes.
 *
 * Failed authentications are counted with the token endpoint's (see client-auth-guard.ts): an
 * address over its failure ceiling is refused with 429 before any secret is verified.
 */
export const clientAuthMiddleware: MiddlewareHandler = async (c, next) => {
  const clientId = c.req.header('x-client-id')
  const clientSecret = c.req.header('x-client-secret')
  const ip = getClientIp(c)

  if (!clientId || !clientSecret) {
    return c.json(
      { error: 'UNAUTHORIZED', message: 'x-client-id and x-client-secret headers required' },
      401,
    )
  }

  try {
    await assertClientAuthAllowed(ip, clientId)
  } catch (err) {
    if (!(err instanceof ApiError) || err.status !== 429) throw err
    c.header('Retry-After', String(Math.ceil(CLIENT_AUTH_FAILURE_WINDOW_MS / 1000)))
    return c.json({ error: 'RATE_LIMITED', message: err.message }, 429)
  }

  const client = await prisma.client.findUnique({ where: { id: clientId } })
  if (!client || !client.active || !client.secretHash) {
    await recordClientAuthFailure(ip, clientId)
    return c.json({ error: 'UNAUTHORIZED', message: 'Unknown or inactive client' }, 401)
  }

  const valid = await verifyClientSecret(ip, clientId, client.secretHash, clientSecret)
  if (!valid) {
    return c.json({ error: 'UNAUTHORIZED', message: 'Invalid client secret' }, 401)
  }

  // Check IP allowlist if configured (supports exact, CIDR, wildcard)
  const allowedIps: string[] = typeof client.allowedIps === 'string'
    ? JSON.parse(client.allowedIps)
    : (client.allowedIps as string[] ?? [])
  if (allowedIps.length > 0) {
    if (!checkIpAllowlist(allowedIps, ip)) {
      return c.json({ error: 'FORBIDDEN', message: 'IP address not allowed for this client' }, 403)
    }
  }

  c.set('clientId', clientId)
  return next()
}
