import { browserClientPolicies } from '../services/browser-policies.js'
import type { MiddlewareHandler } from 'hono'
import { verifyAccessToken, type AccessTokenPayload } from '../services/token-service.js'
import { ApiError } from '../types/index.js'
import { isActorClaim } from '../services/actor-claim.js'
import type { Principal } from '../types/index.js'
import { isRouterProxyPrincipal, routerOperatorAttributed } from '../services/router-operator.js'

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

// Augment Hono context variable map
declare module 'hono' {
  interface ContextVariableMap {
    principal: Principal
  }
}

const USERINFO_PATH = '/api/v1/oauth/userinfo'
/**
 * What a relying party legitimately calls with the access token it was issued: OIDC UserInfo,
 * and sign-out to end the session its sign-in opened.
 */
const RELYING_PARTY_PATHS: ReadonlySet<string> = new Set([USERINFO_PATH, '/api/v1/auth/logout'])

/**
 * Whether a token may call this API at `path`. Native sign-in tokens (no client), service tokens
 * and tokens of a HiveXUI client whose browser policy names the `oathweave` audience manage
 * Oathweave. A person's token issued to any other client is for that client (or the product
 * audience its policy names): it reaches only UserInfo (and, for a relying party, sign-out), so a
 * relying party that holds an administrator's token cannot use it as one here.
 */
function mayUseThisApi(payload: AccessTokenPayload, path: string): boolean {
  if (payload.clientId === 'oathweave-enrollment') return path === USERINFO_PATH
  // A delegated (token-exchange) token is for the downstream audience it names, not this API.
  if (payload['act'] !== undefined) return payload.aud === 'oathweave' || path === USERINFO_PATH
  if (!payload.clientId) return true
  const policy = Object.hasOwn(browserClientPolicies, payload.clientId) ? browserClientPolicies[payload.clientId] : undefined
  if (policy) return policy.audience === 'oathweave' || path === USERINFO_PATH
  // Service tokens (client_credentials, service accounts) carry only what their policy grants.
  if (payload.actorType !== 'USER') return true
  return RELYING_PARTY_PATHS.has(path)
}

export const authMiddleware: MiddlewareHandler = async (c, next) => {
  const authorization = c.req.header('authorization')
  if (!authorization?.startsWith('Bearer ')) {
    return c.json({ error: 'UNAUTHORIZED', message: 'Bearer token required' }, 401)
  }

  const token = authorization.slice(7)
  try {
    const payload = await verifyAccessToken(token)
    if (!mayUseThisApi(payload, c.req.path)) return c.json({ error: 'INVALID_AUDIENCE' }, 401)
    c.set('principal', {
      sub: payload.sub ?? '',
      actorType: payload.actorType as Principal['actorType'],
      email: payload.email,
      username: payload.username,
      roles: payload.roles,
      permissions: payload.permissions,
      sessionId: payload.sessionId,
      clientId: payload.clientId,
      ...(typeof payload['scope'] === 'string' ? { scope: payload['scope'] as string } : {}),
      ...(isActorClaim(payload['act']) ? { act: payload['act'] } : {}),
    })
    const principal = c.get('principal')
    if (
      isRouterProxyPrincipal(principal) &&
      !READ_METHODS.has(c.req.method) &&
      !routerOperatorAttributed(c.req.header('x-hive-operator'))
    ) {
      return c.json(
        { error: 'ROUTER_OPERATOR_REQUIRED', message: 'A write with the Router client token must name the console operator (x-hive-operator)' },
        403,
      )
    }
  } catch (err) {
    if (err instanceof ApiError) {
      return c.json({ error: err.code, message: err.message }, 401)
    }
    return c.json({ error: 'UNAUTHORIZED', message: 'Invalid token' }, 401)
  }

  return next()
}
