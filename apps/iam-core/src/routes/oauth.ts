import { createHash } from 'node:crypto'
import { getBrowserOpenIdConfiguration } from '../services/browser-discovery.js'
import {
  issuerForClient,
  browserClientPolicies,
} from '../services/browser-policies.js'
import {
  browserAuthorization,
  requireBrowserOrigin,
} from '../middleware/browser-session.js'
/**
 * oauth.ts — OAuth2 Authorization Code Flow + PKCE routes.
 *
 * Implements:
 *   GET  /oauth/authorize       — Authorization request (returns client info for consent)
 *   POST /oauth/authorize       — Authorization approval (generates code, redirects)
 *   POST /oauth/token           — Token exchange (code → tokens). A confidential client must
 *                                 authenticate; a public client must have used S256 PKCE.
 *   GET  /oauth/userinfo        — OIDC UserInfo
 *   GET  /oauth/.well-known/openid-configuration — OIDC Discovery
 *   GET  /oauth/jwks            — JSON Web Key Set
 */

import { Hono } from 'hono'
import { prisma } from '../db/client.js'
import { authMiddleware } from '../middleware/auth.js'
import { parseBody } from '../utils/validate.js'
import { getClientIp } from '../utils/ip.js'
import { ApiError } from '../types/index.js'
import {
  AuthorizeQuerySchema,
  AuthorizeConsentSchema,
  TokenExchangeSchema,
} from '../schemas/oauth.js'
import {
  validateAuthorizeRequest,
  createAuthorizationCode,
  authenticateTokenClient,
  exchangeAuthorizationCode,
  exchangeClientCredentials,
  getOpenIdConfiguration,
  getJwks,
} from '../services/oauth-service.js'
import { rotateRefreshToken, issueIdToken } from '../services/token-service.js'
import { env } from '../config/env.js'
import {
  CLIENT_AUTH_FAILURE_WINDOW_MS,
  clientEndpointRateLimit,
} from '../services/client-auth-guard.js'

export const oauthRouter = new Hono()

// ── GET /authorize — Validate request and return client info for consent screen ──
oauthRouter.get('/authorize', browserAuthorization, async (c) => {
  const query = c.req.query()

  const parsed = AuthorizeQuerySchema.safeParse(query)
  if (!parsed.success) {
    const messages = parsed.error.issues
      .map((i) => `${i.path.join('.')}: ${i.message}`)
      .join('; ')
    throw new ApiError(400, 'INVALID_REQUEST', messages)
  }

  const params = parsed.data

  const result = await validateAuthorizeRequest({
    clientId: params.client_id,
    redirectUri: params.redirect_uri,
    responseType: params.response_type,
    codeChallenge: params.code_challenge,
    codeChallengeMethod: params.code_challenge_method,
    scope: params.scope,
    state: params.state,
    nonce: params.nonce,
  })

  // If first-party client, auto-approve and redirect immediately
  if (result.skipConsent) {
    const principal = c.get('principal')
    const codeResult = await createAuthorizationCode(
      principal.sub,
      {
        clientId: params.client_id,
        redirectUri: params.redirect_uri,
        responseType: params.response_type,
        codeChallenge: params.code_challenge,
        codeChallengeMethod: params.code_challenge_method,
        scope: params.scope,
        state: params.state,
        browserSessionId: browserClientPolicies[params.client_id]
          ? principal.sessionId
          : undefined,
        nonce: params.nonce,
      },
      getClientIp(c),
    )

    const redirectUrl = new URL(codeResult.redirectUri)
    redirectUrl.searchParams.set('code', codeResult.code)
    if (codeResult.state)
      redirectUrl.searchParams.set('state', codeResult.state)

    return c.redirect(redirectUrl.toString(), 302)
  }

  // Return client info for consent screen
  return c.json({
    clientName: result.clientName,
    clientDescription: result.clientDescription,
    scope: result.scope,
    // Echo back the params so the consent form can re-submit them
    authParams: {
      clientId: params.client_id,
      redirectUri: params.redirect_uri,
      responseType: params.response_type,
      codeChallenge: params.code_challenge,
      codeChallengeMethod: params.code_challenge_method,
      scope: params.scope,
      state: params.state,
      nonce: params.nonce,
    },
  })
})

// ── POST /authorize — User approves consent, generate code and redirect ──
oauthRouter.post('/authorize', browserAuthorization, async (c) => {
  const body = await parseBody(c, AuthorizeConsentSchema)
  const principal = c.get('principal')
  const ip = getClientIp(c)

  // A browser preflight must not allocate a usable code before consent. Native
  // clients retain their existing explicit POST approval flow.
  const browser =
    c.req.header('x-oathweave-browser') === 'true' &&
    browserClientPolicies[body.clientId]
  if (browser) {
    requireBrowserOrigin(c)
    const request = await validateAuthorizeRequest(body)
    c.header('Cache-Control', 'no-store')
    if (body.consent === 'deny')
      return c.json(
        { error: 'ACCESS_DENIED', message: 'Authorization declined' },
        403,
      )
    if (!request.skipConsent && body.consent !== 'approve') {
      return c.json(
        {
          error: 'CONSENT_REQUIRED',
          message: 'Review access before continuing',
          clientName: request.clientName,
          clientDescription: request.clientDescription,
          scope: request.scope ?? '',
          audience: browserClientPolicies[body.clientId]!.audience,
          permissions: browserClientPolicies[body.clientId]!.permissions.filter(
            (permission) =>
              principal.permissions.includes(permission) ||
              principal.permissions.includes('*'),
          ),
        },
        403,
      )
    }
  }

  const codeResult = await createAuthorizationCode(
    principal.sub,
    {
      clientId: body.clientId,
      redirectUri: body.redirectUri,
      responseType: body.responseType,
      codeChallenge: body.codeChallenge,
      codeChallengeMethod: body.codeChallengeMethod,
      scope: body.scope,
      state: body.state,
      nonce: body.nonce,
      browserSessionId: browserClientPolicies[body.clientId]
        ? principal.sessionId
        : undefined,
    },
    ip,
  )

  // Same-origin first-party SPA clients receive the authorization response
  // directly. The code still requires its registered redirect URI and PKCE.
  if (
    c.req.header('x-oathweave-browser') === 'true' &&
    browserClientPolicies[body.clientId]
  ) {
    requireBrowserOrigin(c)
    c.header('Cache-Control', 'no-store')
    return c.json({
      code: codeResult.code,
      state: codeResult.state,
      iss: issuerForClient(body.clientId, env.JWT_ISSUER),
    })
  }

  const redirectUrl = new URL(codeResult.redirectUri)
  redirectUrl.searchParams.set('code', codeResult.code)
  if (codeResult.state) redirectUrl.searchParams.set('state', codeResult.state)

  return c.json({
    redirectUri: redirectUrl.toString(),
    code: codeResult.code,
    state: codeResult.state,
  })
})

// ── POST /token — Exchange code for tokens (or refresh) ──
oauthRouter.post('/token', clientEndpointRateLimit('rl:token'), async (c) => {
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
  // Parse as form-urlencoded (OAuth2 spec) or JSON
  let body: Record<string, string>
  const contentType = c.req.header('content-type') ?? ''

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await c.req.parseBody()
    body = Object.fromEntries(
      Object.entries(formData).map(([k, v]) => [k, String(v)]),
    )
  } else {
    try {
      body = (await c.req.json()) as Record<string, string>
    } catch {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'Request body is not valid JSON',
        },
        400,
      )
    }
  }

  const parsed = TokenExchangeSchema.safeParse(body)
  if (!parsed.success) {
    const messages = parsed.error.issues
      .map((i) => `${i.path.join('.')}: ${i.message}`)
      .join('; ')
    return c.json(
      { error: 'invalid_request', error_description: messages },
      400,
    )
  }

  const params = parsed.data
  const ip = getClientIp(c)

  // Client identification (RFC 6749 §2.3.1): the body, or HTTP Basic (client_secret_basic).
  const basic = extractBasicCredentials(c)
  if (basic && params.client_id !== undefined && params.client_id !== basic.clientId) {
    return c.json(
      {
        error: 'invalid_request',
        error_description: 'client_id in the body does not match the Basic credentials',
      },
      400,
    )
  }
  const clientId = params.client_id ?? basic?.clientId
  const presentedSecret = params.client_secret ?? basic?.clientSecret

  /** Authenticates the client; returns the error response when it is refused. */
  const authenticate = async (
    id: string,
  ): Promise<{ authenticated: boolean } | Response> => {
    try {
      return await authenticateTokenClient(id, presentedSecret, ip)
    } catch (err) {
      if (!(err instanceof ApiError)) throw err
      if (err.status === 429) {
        c.header('Retry-After', String(Math.ceil(CLIENT_AUTH_FAILURE_WINDOW_MS / 1000)))
      } else if (basic) {
        c.header('WWW-Authenticate', 'Basic realm="oauth"')
      }
      return c.json(
        { error: err.code.toLowerCase(), error_description: err.message },
        err.status as 401,
      )
    }
  }

  // ── Handle refresh_token grant ──
  if (params.grant_type === 'refresh_token') {
    if (!params.refresh_token) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'refresh_token required',
        },
        400,
      )
    }

    // A confidential client must authenticate to refresh (RFC 6749 §6); a public client is
    // identified by its client_id alone. The refresh token's own binding is checked on rotation.
    let clientAuthenticated = false
    if (clientId) {
      const auth = await authenticate(clientId)
      if (auth instanceof Response) return auth
      clientAuthenticated = auth.authenticated
    }

    try {
      const tokenPair = await rotateRefreshToken(
        params.refresh_token,
        ip,
        clientId,
        c.req.header('user-agent'),
        { clientAuthenticated },
      )
      return c.json({
        access_token: tokenPair.accessToken,
        refresh_token: tokenPair.refreshToken,
        expires_in: tokenPair.expiresIn,
        token_type: 'Bearer',
      })
    } catch (err) {
      if (err instanceof ApiError && err.code === 'INVALID_CLIENT') {
        return c.json({ error: 'invalid_client', error_description: err.message }, 401)
      }
      if (err instanceof ApiError && err.code === 'UNAUTHORIZED_CLIENT') {
        return c.json({ error: 'unauthorized_client', error_description: err.message }, 400)
      }
      return c.json(
        {
          error: 'invalid_grant',
          error_description:
            err instanceof Error ? err.message : 'Invalid refresh token',
        },
        400,
      )
    }
  }

  // ── Handle client_credentials grant ──
  if (params.grant_type === 'client_credentials') {
    if (!clientId) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'client_id is required',
        },
        400,
      )
    }

    // Authenticate the client (required for client_credentials)
    const auth = await authenticate(clientId)
    if (auth instanceof Response) return auth
    if (!auth.authenticated) {
      return c.json(
        {
          error: 'invalid_client',
          error_description: 'Client authentication required',
        },
        401,
      )
    }

    try {
      const result = await exchangeClientCredentials(
        clientId,
        params.scope,
        ip,
      )
      return c.json({
        access_token: result.accessToken,
        expires_in: result.expiresIn,
        token_type: result.tokenType,
        scope: result.scope,
      })
    } catch (err) {
      if (err instanceof ApiError) {
        return c.json(
          { error: err.code.toLowerCase(), error_description: err.message },
          err.status as 400,
        )
      }
      return c.json(
        {
          error: 'server_error',
          error_description: 'An unexpected error occurred',
        },
        500,
      )
    }
  }

  // ── Handle authorization_code grant ──
  if (!params.code || !params.redirect_uri || !clientId) {
    return c.json(
      {
        error: 'invalid_request',
        error_description: 'code, redirect_uri, and client_id are required',
      },
      400,
    )
  }

  // Bind the exchange to the client: a confidential client must authenticate with its secret
  // (body or Basic auth); a public client is bound by PKCE, enforced with the code below.
  const auth = await authenticate(clientId)
  if (auth instanceof Response) return auth
  const clientAuthenticated = auth.authenticated

  try {
    const result = await exchangeAuthorizationCode(
      {
        grantType: params.grant_type,
        code: params.code,
        redirectUri: params.redirect_uri,
        clientId,
        codeVerifier: params.code_verifier,
        clientAuthenticated,
      },
      ip,
    )

    const response: Record<string, unknown> = {
      access_token: result.accessToken,
      refresh_token: result.refreshToken,
      expires_in: result.expiresIn,
      token_type: result.tokenType,
      scope: result.scope,
    }

    // Issue id_token when openid is one of the granted scope tokens (OIDC compliance)
    if (result.scope?.split(/\s+/).includes('openid') && result.userId) {
      const idToken = await issueIdToken(
        result.userId,
        result.email ?? '',
        result.username ?? '',
        result.displayName ?? '',
        clientId,
        result.nonce,
        result.accessToken,
      )
      response['id_token'] = idToken
    }

    if (browserClientPolicies[clientId]) {
      await prisma.refreshToken.deleteMany({
        where: {
          tokenHash: createHash('sha256')
            .update(result.refreshToken)
            .digest('hex'),
        },
      })
      delete response.refresh_token
    }
    return c.json(response)
  } catch (err) {
    if (err instanceof ApiError) {
      return c.json(
        {
          error: err.code.toLowerCase(),
          error_description: err.message,
        },
        err.status as 400,
      )
    }
    return c.json(
      {
        error: 'server_error',
        error_description: 'An unexpected error occurred',
      },
      500,
    )
  }
})

// ── GET /userinfo — OIDC UserInfo endpoint ──
oauthRouter.get('/userinfo', authMiddleware, async (c) => {
  const principal = c.get('principal')

  const user = await prisma.user.findUnique({
    where: { id: principal.sub },
    select: {
      id: true,
      email: true,
      username: true,
      displayName: true,
      roles: { include: { role: { select: { name: true } } } },
    },
  })

  if (!user) {
    throw new ApiError(404, 'NOT_FOUND', 'User not found')
  }

  return c.json({
    sub: user.id,
    email: user.email,
    preferred_username: user.username,
    name: user.displayName,
    roles: user.roles.map((r) => r.role.name),
  })
})

// ── GET /.well-known/openid-configuration — OIDC Discovery ──
oauthRouter.get('/.well-known/openid-configuration', async (c) => {
  const clients = c.req.queries('client_id')
  if (clients) {
    c.header('Cache-Control', 'no-store')
    if (clients.length !== 1 || !clients[0]) throw new ApiError(400, 'INVALID_CLIENT', 'Select one registered public browser client')
    return c.json(await getBrowserOpenIdConfiguration(clients[0]))
  }
  const proto = c.req.header('x-forwarded-proto') ?? 'https'
  const host =
    c.req.header('x-forwarded-host') ?? c.req.header('host') ?? 'localhost:4200'
  const issuerUrl = `${proto}://${host}`

  c.header('Cache-Control', 'public, max-age=86400')
  return c.json(getOpenIdConfiguration(issuerUrl))
})

// ── GET /jwks — JSON Web Key Set ──
oauthRouter.get('/jwks', async (c) => {
  c.header('Cache-Control', 'public, max-age=3600')
  const jwks = await getJwks()
  return c.json(jwks)
})

// ── Helper: client credentials from the Basic auth header (RFC 6749 §2.3.1) ──
/** Reverses application/x-www-form-urlencoded encoding; a malformed value is used as sent. */
function formUrlDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '))
  } catch {
    return value
  }
}

export function extractBasicCredentials(c: {
  req: { header: (name: string) => string | undefined }
}): { clientId: string; clientSecret: string } | undefined {
  const authorization = c.req.header('authorization')
  if (!authorization || !/^basic /i.test(authorization)) return undefined

  const decoded = Buffer.from(authorization.slice(6).trim(), 'base64').toString('utf-8')
  const colonIndex = decoded.indexOf(':')
  if (colonIndex === -1) return undefined
  const clientId = formUrlDecode(decoded.slice(0, colonIndex))
  if (!clientId) return undefined
  return { clientId, clientSecret: formUrlDecode(decoded.slice(colonIndex + 1)) }
}
