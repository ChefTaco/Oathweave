/**
 * Standard OAuth / OpenID Connect endpoints for generic relying parties, next to the routes in
 * oauth.ts:
 *
 *   POST /oauth/revoke      — RFC 7009 revocation, client_secret_basic / client_secret_post / none
 *   POST /oauth/introspect  — RFC 7662 introspection, confidential clients only
 *   GET|POST /oauth/logout  — OpenID Connect RP-Initiated Logout 1.0 (end_session_endpoint)
 *   POST /oauth/device_authorization — RFC 8628 device authorization request
 *   GET|POST /oauth/device  — a signed-in person looks up and approves or denies a user code
 *
 * The older `/tokens/revoke` and `/tokens/introspect` (x-client-id / x-client-secret headers)
 * remain; both pairs share token-introspection.ts, so a client reaches only its own tokens.
 */
import type { Context } from 'hono'
import { Hono } from 'hono'
import { compactVerify, createLocalJWKSet } from 'jose'
import { getCookie } from 'hono/cookie'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { ApiError } from '../types/index.js'
import { getClientIp } from '../utils/ip.js'
import { getPublishedSigningJwks } from '../utils/keys.js'
import { logAuditEvent } from '../services/audit-service.js'
import { authenticateTokenClient } from '../services/oauth-service.js'
import { CLIENT_AUTH_FAILURE_WINDOW_MS, clientEndpointRateLimit } from '../services/client-auth-guard.js'
import { introspectForClient, revokeForClient, tokenClientAuthority } from '../services/token-introspection.js'
import { revokeSession } from '../services/session-service.js'
import { browserClientPolicies, issuerForClient } from '../services/browser-policies.js'
import { browserAuthorization, browserPrincipal, clearBrowserSessionCookie } from '../middleware/browser-session.js'
import { parsePermissionList } from '../services/effective-grants.js'
import { extractBasicCredentials } from './oauth.js'
import { z } from 'zod'
import { parseBody } from '../utils/validate.js'
import { rateLimitMiddleware } from '../middleware/rate-limit.js'
import { decideDeviceAuthorization, describeDeviceAuthorization, startDeviceAuthorization } from '../services/device-authorization.js'

export const oauthStandardRouter = new Hono()

/** An OAuth request body: form-encoded as the RFCs specify, or JSON. */
export async function readOAuthParameters(c: Context): Promise<Record<string, string>> {
  const contentType = c.req.header('content-type') ?? ''
  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    const form = await c.req.parseBody()
    return Object.fromEntries(Object.entries(form).filter(([, value]) => typeof value === 'string')) as Record<string, string>
  }
  if (contentType.includes('application/json')) {
    const body: unknown = await c.req.json().catch(() => undefined)
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new ApiError(400, 'INVALID_REQUEST', 'Request body is not valid JSON')
    return Object.fromEntries(Object.entries(body).filter(([, value]) => typeof value === 'string')) as Record<string, string>
  }
  return {}
}

function oauthError(c: Context, status: 400 | 401 | 429, error: string, description: string) {
  c.header('Cache-Control', 'no-store')
  return c.json({ error, error_description: description }, status)
}

/** The calling client, authenticated as at the token endpoint; a Response when it is refused. */
export async function callingClient(c: Context, body: Record<string, string>): Promise<{ clientId: string; authenticated: boolean } | Response> {
  const basic = extractBasicCredentials(c)
  if (basic && body['client_id'] !== undefined && body['client_id'] !== basic.clientId)
    return oauthError(c, 400, 'invalid_request', 'client_id in the body does not match the Basic credentials')
  const clientId = body['client_id'] ?? basic?.clientId
  if (!clientId) {
    c.header('WWW-Authenticate', 'Basic realm="oauth"')
    return oauthError(c, 401, 'invalid_client', 'Client authentication required')
  }
  try {
    const result = await authenticateTokenClient(clientId, body['client_secret'] ?? basic?.clientSecret, getClientIp(c))
    return { clientId, authenticated: result.authenticated }
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
    if (err.status === 429) {
      c.header('Retry-After', String(Math.ceil(CLIENT_AUTH_FAILURE_WINDOW_MS / 1000)))
      return oauthError(c, 429, 'slow_down', err.message)
    }
    if (basic) c.header('WWW-Authenticate', 'Basic realm="oauth"')
    return oauthError(c, 401, 'invalid_client', err.message)
  }
}

const HINTS = new Set(['access_token', 'refresh_token'])

oauthStandardRouter.post('/revoke', clientEndpointRateLimit('rl:revoke'), async (c) => {
  const body = await readOAuthParameters(c)
  const client = await callingClient(c, body)
  if (client instanceof Response) return client
  const token = body['token']
  if (!token) return oauthError(c, 400, 'invalid_request', 'token is required')
  const hint = body['token_type_hint']
  // RFC 7009 §2.1: an unknown hint is ignored, not refused.
  const authority = tokenClientAuthority(client.clientId)
  const result = await revokeForClient(
    // A public client is identified, not authenticated: it reaches only its own tokens.
    client.authenticated ? authority : { ...authority, revokeAny: false },
    token,
    hint && HINTS.has(hint) ? (hint as 'access_token' | 'refresh_token') : undefined,
  )
  if (result.outcome === 'forbidden') return oauthError(c, 400, 'unauthorized_client', 'The token was not issued to this client')
  if (result.outcome === 'revoked') {
    await logAuditEvent({
      eventType: 'token.revoked',
      category: 'TOKEN',
      actorId: result.subject,
      actorType: result.actorType === 'USER' ? 'USER' : 'SERVICE_ACCOUNT',
      clientId: client.clientId,
      ipAddress: getClientIp(c),
      action: 'revoke',
      outcome: 'SUCCESS',
      detail: { tokenType: result.tokenType },
      source: 'iam-api',
    })
  }
  c.header('Cache-Control', 'no-store')
  return c.body(null, 200)
})

oauthStandardRouter.post('/introspect', clientEndpointRateLimit('rl:introspect'), async (c) => {
  const body = await readOAuthParameters(c)
  const client = await callingClient(c, body)
  if (client instanceof Response) return client
  if (!client.authenticated) return oauthError(c, 401, 'invalid_client', 'Introspection requires an authenticated confidential client')
  const token = body['token']
  if (!token) return oauthError(c, 400, 'invalid_request', 'token is required')
  c.header('Cache-Control', 'no-store')
  return c.json(await introspectForClient(tokenClientAuthority(client.clientId), token))
})

/** Issuers whose id_tokens this server signed: native, and each browser client's. */
function knownIssuers(): Set<string> {
  return new Set([env.JWT_ISSUER, ...Object.keys(browserClientPolicies).map((id) => issuerForClient(id, env.JWT_ISSUER))])
}

/**
 * An id_token_hint this server issued. Its signature and issuer are checked; its expiry is not,
 * because RP-initiated logout routinely presents an expired id_token (OIDC RP-Initiated Logout §2).
 */
async function idTokenHint(raw: string): Promise<{ sub: string; aud: string | undefined; sid: string | undefined } | undefined> {
  try {
    const { payload } = await compactVerify(raw, createLocalJWKSet(await getPublishedSigningJwks()), { algorithms: ['RS256'] })
    const claims = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>
    if (typeof claims['iss'] !== 'string' || !knownIssuers().has(claims['iss'])) return undefined
    if (typeof claims['sub'] !== 'string' || !claims['sub']) return undefined
    const audience = claims['aud']
    const aud = typeof audience === 'string' ? audience : Array.isArray(audience) && audience.length === 1 && typeof audience[0] === 'string' ? audience[0] : undefined
    return { sub: claims['sub'], aud, sid: typeof claims['sid'] === 'string' ? claims['sid'] : undefined }
  } catch {
    return undefined
  }
}

async function endSession(c: Context, parameters: Record<string, string | undefined>) {
  c.header('Cache-Control', 'no-store')
  const ip = getClientIp(c)
  let hint: Awaited<ReturnType<typeof idTokenHint>>
  if (parameters['id_token_hint']) {
    hint = await idTokenHint(parameters['id_token_hint'])
    if (!hint) return oauthError(c, 400, 'invalid_request', 'id_token_hint was not issued by this server')
  }
  if (hint?.aud && parameters['client_id'] && hint.aud !== parameters['client_id'])
    return oauthError(c, 400, 'invalid_request', 'client_id does not match the id_token_hint audience')
  const clientId = parameters['client_id'] ?? hint?.aud

  // Validate the return address before signing anyone out, so a bad request changes nothing.
  const redirect = parameters['post_logout_redirect_uri']
  if (redirect !== undefined) {
    if (!clientId) return oauthError(c, 400, 'invalid_request', 'post_logout_redirect_uri needs id_token_hint or client_id')
    const client = await prisma.client.findUnique({ where: { id: clientId }, select: { active: true, redirectUris: true } })
    if (!client?.active || !parsePermissionList(client.redirectUris).includes(redirect))
      return oauthError(c, 400, 'invalid_request', 'post_logout_redirect_uri is not registered for this client')
  }

  const ended: string[] = []
  if (hint?.sid) {
    const session = await prisma.session.findUnique({ where: { id: hint.sid }, select: { userId: true } })
    if (session?.userId === hint.sub && (await revokeSession(hint.sid, 'rp_logout', { reason: 'sign_out' }))) ended.push(hint.sid)
  }
  // The suite browser session (a SameSite=Strict cookie, so only a same-site request carries it).
  if (getCookie(c, '__Host-oathweave_sso')) {
    const browser = await browserPrincipal(c)
    if (browser?.sessionId && !ended.includes(browser.sessionId) && (await revokeSession(browser.sessionId, 'rp_logout', { reason: 'sign_out' }))) ended.push(browser.sessionId)
    clearBrowserSessionCookie(c)
  }
  if (ended.length > 0) {
    await logAuditEvent({
      eventType: 'auth.logout',
      category: 'AUTHENTICATION',
      actorId: hint?.sub,
      actorType: 'USER',
      ipAddress: ip,
      action: 'rp_initiated_logout',
      outcome: 'SUCCESS',
      detail: { clientId, sessions: ended.length },
      source: 'iam-api',
    })
  }

  if (redirect !== undefined) {
    const target = new URL(redirect)
    if (parameters['state']) target.searchParams.set('state', parameters['state'])
    return c.redirect(target.toString(), 302)
  }
  return c.json({ signedOut: ended.length > 0 })
}

oauthStandardRouter.get('/logout', (c) => endSession(c, c.req.query()))
oauthStandardRouter.post('/logout', async (c) => endSession(c, await readOAuthParameters(c)))

// ── Device Authorization Grant (RFC 8628) ──

oauthStandardRouter.post('/device_authorization', clientEndpointRateLimit('rl:device'), async (c) => {
  const body = await readOAuthParameters(c)
  const client = await callingClient(c, body)
  if (client instanceof Response) return client
  try {
    const response = await startDeviceAuthorization(client.clientId, body['scope'] || undefined, getClientIp(c))
    c.header('Cache-Control', 'no-store')
    return c.json(response)
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
    c.header('Cache-Control', 'no-store')
    return c.json({ error: err.code.toLowerCase(), error_description: err.message }, err.status as 400)
  }
})

const DeviceDecisionSchema = z.object({ userCode: z.string().min(1).max(32), decision: z.enum(['approve', 'deny']) })
const deviceCodeEntry = rateLimitMiddleware({ keyPrefix: 'rl:device-user-code', max: 10, windowMs: 300_000, authAttempt: true })

function interactivePerson(c: Context): { userId: string; sessionId: string } {
  const principal = c.get('principal')
  if (principal.actorType !== 'USER' || !principal.sessionId) throw new ApiError(403, 'FORBIDDEN', 'Interactive session required')
  return { userId: principal.sub, sessionId: principal.sessionId }
}

/** The approval page reads which client asks, before the person decides. */
oauthStandardRouter.get('/device', deviceCodeEntry, browserAuthorization, async (c) => {
  interactivePerson(c)
  const userCode = c.req.query('user_code')
  if (!userCode) throw new ApiError(400, 'VALIDATION_ERROR', 'user_code is required')
  c.header('Cache-Control', 'no-store')
  return c.json(await describeDeviceAuthorization(userCode))
})

oauthStandardRouter.post('/device', deviceCodeEntry, browserAuthorization, async (c) => {
  const person = interactivePerson(c)
  const { userCode, decision } = await parseBody(c, DeviceDecisionSchema)
  await decideDeviceAuthorization(userCode, person, decision, getClientIp(c))
  c.header('Cache-Control', 'no-store')
  return c.json({ success: true, decision })
})
