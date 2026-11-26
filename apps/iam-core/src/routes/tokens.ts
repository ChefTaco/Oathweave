import { Hono } from 'hono'
import { clientAuthMiddleware } from '../middleware/client-auth.js'
import { clientEndpointRateLimit } from '../services/client-auth-guard.js'
import { authMiddleware } from '../middleware/auth.js'
import { revokeRefreshToken, verifyAccessToken } from '../services/token-service.js'
import { introspectForClient, revokeForClient, tokenClientAuthority } from '../services/token-introspection.js'
import { revokeSession } from '../services/session-service.js'
import { logAuditEvent } from '../services/audit-service.js'
import { getClientIp } from '../utils/ip.js'
import { parseBody } from '../utils/validate.js'
import type { ActorType } from '../types/index.js'
import { z } from 'zod'

export const tokensRouter = new Hono()

const IntrospectSchema = z.object({ token: z.string().min(1) })
const RevokeSchema = z.object({ token: z.string().min(1) })
const OAuthRevokeSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
})

// POST /tokens/introspect — callable by registered clients (RFC 7662). A client sees the tokens
// issued to it; seeing any token needs iam:tokens:introspect (see token-introspection.ts).
tokensRouter.post('/introspect', clientEndpointRateLimit('rl:introspect'), clientAuthMiddleware, async (c) => {
  const { token } = await parseBody(c, IntrospectSchema)
  const clientId = c.get('clientId')
  c.header('Cache-Control', 'no-store')
  const result = await introspectForClient(tokenClientAuthority(clientId), token)

  if (result.active) {
    await logAuditEvent({
      eventType: 'token.introspect',
      category: 'TOKEN',
      actorId: String(result['sub'] ?? ''),
      actorType: result['actor_type'] as ActorType,
      clientId,
      ipAddress: getClientIp(c),
      action: 'introspect',
      outcome: 'SUCCESS',
      source: 'iam-api',
    })
  }
  return c.json(result)
})

// POST /tokens/revoke — RFC 7009 token revocation (client-authenticated). A client revokes the
// tokens issued to it; revoking any token needs iam:tokens:revoke.
tokensRouter.post('/revoke', clientEndpointRateLimit('rl:revoke'), clientAuthMiddleware, async (c) => {
  const { token, token_type_hint } = await parseBody(c, OAuthRevokeSchema)
  const clientId = c.get('clientId')
  const result = await revokeForClient(tokenClientAuthority(clientId), token, token_type_hint)

  if (result.outcome === 'forbidden') {
    await logAuditEvent({
      eventType: 'token.revoke_denied',
      category: 'TOKEN',
      actorId: clientId,
      actorType: 'SERVICE_ACCOUNT',
      clientId,
      ipAddress: getClientIp(c),
      action: 'revoke',
      outcome: 'DENIED',
      detail: { reason: 'token_issued_to_another_client' },
      source: 'iam-api',
    })
    return c.json({ error: 'unauthorized_client', error_description: 'The token was not issued to this client' }, 400)
  }
  if (result.outcome === 'revoked') {
    await logAuditEvent({
      eventType: 'token.revoked',
      category: 'TOKEN',
      actorId: result.subject,
      actorType: result.actorType as ActorType,
      clientId,
      ipAddress: getClientIp(c),
      action: 'revoke',
      outcome: 'SUCCESS',
      detail: { tokenType: result.tokenType },
      source: 'iam-api',
    })
  }

  // RFC 7009: an unknown or already invalid token is answered with 200 too.
  return c.json({ success: true })
})

// POST /tokens/revoke-own — authenticated user can revoke their own token
tokensRouter.post('/revoke-own', authMiddleware, async (c) => {
  const principal = c.get('principal')
  const { token } = await parseBody(c, RevokeSchema)

  // Verify the token belongs to the calling user before revoking
  try {
    const payload = await verifyAccessToken(token)
    if (payload.sub !== principal.sub) {
      return c.json({ error: 'FORBIDDEN', message: 'Cannot revoke another user\'s token' }, 403)
    }
    // Revoke the associated session
    if (payload.sessionId) {
      await revokeSession(payload.sessionId, principal.sub)
    }
  } catch {
    // If the token is invalid / expired, treat it as one of the caller's refresh tokens
    await revokeRefreshToken(token, { userId: principal.sub })
    return c.json({ success: true })
  }

  await logAuditEvent({
    eventType: 'token.revoked',
    category: 'TOKEN',
    actorId: principal.sub,
    actorType: principal.actorType,
    actorEmail: principal.email,
    ipAddress: getClientIp(c),
    action: 'revoke',
    outcome: 'SUCCESS',
    source: 'iam-api',
  })

  return c.json({ success: true })
})
