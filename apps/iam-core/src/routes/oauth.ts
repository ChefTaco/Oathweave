import { sha256Hex } from '@hivemagnus/hive-common/secrets'
import { getBrowserOpenIdConfiguration } from '../services/browser-discovery.js'
import {
  issuerForClient,
  browserClientPolicies,
} from '../services/browser-policies.js'
import {
  optionalBrowserAuthorization,
  requireBrowserOrigin,
} from '../middleware/browser-session.js'
import {
  authorizationErrorResponse,
  evaluatePrompt,
  loginRequiredBody,
} from '../services/authorization-prompt.js'
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

import { Hono, type Context } from 'hono'
import { prisma } from '../db/client.js'
import { authMiddleware } from '../middleware/auth.js'
import { parseBody } from '../utils/validate.js'
import { getClientIp } from '../utils/ip.js'
import { ApiError, type Principal } from '../types/index.js'
import {
  AuthorizeQuerySchema,
  AuthorizeConsentSchema,
  AuthorizeCancelSchema,
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
import { rotateRefreshToken, issueIdToken, scopeTokens } from '../services/token-service.js'
import { env } from '../config/env.js'
import { userTokenGrants } from '../services/effective-grants.js'
import { clientAllowsDeviceGrant, DEVICE_CODE_GRANT, exchangeDeviceCode } from '../services/device-authorization.js'
import { ACCESS_TOKEN_TYPE, exchangeToken, TOKEN_EXCHANGE_GRANT } from '../services/token-exchange.js'
import {
  CLIENT_AUTH_FAILURE_WINDOW_MS,
  clientEndpointRateLimit,
} from '../services/client-auth-guard.js'

export const oauthRouter = new Hono()

// ── GET /authorize — Validate request and return client info for consent screen ──
// Honours OpenID Connect prompt (none, login, consent, select_account) and max_age; see
// services/authorization-prompt.ts.
oauthRouter.get('/authorize', optionalBrowserAuthorization, async (c) => {
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

  const binding = {
    clientId: params.client_id,
    redirectUri: params.redirect_uri,
    state: params.state,
    nonce: params.nonce,
    codeChallenge: params.code_challenge,
  }
  const principal = c.get('principal') as Principal | undefined
  const outcome = await evaluatePrompt(principal, { prompt: params.prompt, maxAge: params.max_age, loginTicket: params.login_ticket }, binding)
  if (!outcome.ok) {
    c.header('Cache-Control', 'no-store')
    // prompt=none: the error goes back to the (validated) client callback.
    if (outcome.prompts.has('none'))
      return c.redirect(authorizationErrorResponse(binding, 'login_required', 'Sign-in is required').redirectTo, 302)
    return c.json(await loginRequiredBody(outcome.reason, binding), 401)
  }
  const signedIn = principal!
  const forceConsent = outcome.prompts.has('consent')
  if (outcome.prompts.has('none') && (!result.skipConsent || forceConsent))
    return c.redirect(authorizationErrorResponse(binding, 'consent_required', 'Consent is required').redirectTo, 302)

  // If first-party client, auto-approve and redirect immediately
  if (result.skipConsent && !forceConsent) {
    const codeResult = await createAuthorizationCode(
      signedIn.sub,
      {
        clientId: params.client_id,
        redirectUri: params.redirect_uri,
        responseType: params.response_type,
        codeChallenge: params.code_challenge,
        codeChallengeMethod: params.code_challenge_method,
        scope: params.scope,
        state: params.state,
        browserSessionId: browserClientPolicies[params.client_id]
          ? signedIn.sessionId
          : undefined,
        authSessionId: signedIn.sessionId,
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
      ...(params.prompt !== undefined ? { prompt: params.prompt } : {}),
      ...(params.max_age !== undefined ? { maxAge: params.max_age } : {}),
      ...(params.login_ticket !== undefined ? { loginTicket: params.login_ticket } : {}),
    },
  })
})

// ── POST /authorize — User approves consent, generate code and redirect ──
// Honours prompt and max_age as GET does. A request that must end at the client (prompt=none
// needing an interaction, or declined consent) carries `redirectTo`, the validated callback
// with the OAuth error, state and iss.
oauthRouter.post('/authorize', optionalBrowserAuthorization, async (c) => {
  const body = await parseBody(c, AuthorizeConsentSchema)
  const ip = getClientIp(c)

  // A browser preflight must not allocate a usable code before consent. Native
  // clients retain their existing explicit POST approval flow.
  const browser =
    c.req.header('x-oathweave-browser') === 'true' &&
    Boolean(browserClientPolicies[body.clientId])
  if (browser) requireBrowserOrigin(c)
  const request = await validateAuthorizeRequest(body)
  const binding = {
    clientId: body.clientId,
    redirectUri: body.redirectUri,
    state: body.state,
    nonce: body.nonce,
    codeChallenge: body.codeChallenge,
  }
  const principal = c.get('principal') as Principal | undefined
  const outcome = await evaluatePrompt(principal, body, binding)
  if (!outcome.ok) {
    c.header('Cache-Control', 'no-store')
    if (outcome.prompts.has('none'))
      return c.json(authorizationErrorResponse(binding, 'login_required', 'Sign-in is required'), 400)
    return c.json(await loginRequiredBody(outcome.reason, binding), 401)
  }
  const signedIn = principal!
  // A declined authorization never allocates a code, for browser and native callers alike.
  if (body.consent === 'deny') {
    c.header('Cache-Control', 'no-store')
    return c.json(
      {
        error: 'ACCESS_DENIED',
        message: 'Authorization declined',
        redirectTo: authorizationErrorResponse(binding, 'access_denied', 'The user declined access').redirectTo,
      },
      403,
    )
  }
  if (browser) {
    c.header('Cache-Control', 'no-store')
    const consentNeeded = !request.skipConsent || outcome.prompts.has('consent')
    if (consentNeeded && body.consent !== 'approve') {
      if (outcome.prompts.has('none'))
        return c.json(authorizationErrorResponse(binding, 'consent_required', 'Consent is required'), 400)
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
              signedIn.permissions.includes(permission) ||
              signedIn.permissions.includes('*'),
          ),
        },
        403,
      )
    }
  }

  const codeResult = await createAuthorizationCode(
    signedIn.sub,
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
        ? signedIn.sessionId
        : undefined,
      authSessionId: signedIn.sessionId,
    },
    ip,
  )

  // Same-origin first-party SPA clients receive the authorization response
  // directly. The code still requires its registered redirect URI and PKCE.
  if (browser) {
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

// ── POST /authorize/cancel — The user abandoned sign-in or consent ──
// Needs no sign-in: it creates nothing and answers only for a registered client and its exact
// redirect URI, with `redirectTo` carrying error=access_denied, the state and iss.
oauthRouter.post('/authorize/cancel', clientEndpointRateLimit('rl:authorize-cancel'), async (c) => {
  if (c.req.header('x-oathweave-browser') !== 'true')
    throw new ApiError(400, 'INVALID_REQUEST', 'Cancellation is a browser request')
  requireBrowserOrigin(c)
  const body = await parseBody(c, AuthorizeCancelSchema)
  if (!browserClientPolicies[body.clientId])
    throw new ApiError(400, 'INVALID_CLIENT', 'Select a registered public browser client')
  await validateAuthorizeRequest(body)
  c.header('Cache-Control', 'no-store')
  return c.json(
    authorizationErrorResponse(
      { clientId: body.clientId, redirectUri: body.redirectUri, state: body.state },
      'access_denied',
      'The user cancelled sign-in',
    ),
  )
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

  // ── Handle the device authorization grant (RFC 8628 §3.4) ──
  if (params.grant_type === DEVICE_CODE_GRANT) {
    if (!params.device_code || !clientId) {
      return c.json({ error: 'invalid_request', error_description: 'device_code and client_id are required' }, 400)
    }
    const auth = await authenticate(clientId)
    if (auth instanceof Response) return auth
    try {
      const client = await prisma.client.findUnique({ where: { id: clientId }, select: { clientType: true, grantTypes: true } })
      if (!client || !clientAllowsDeviceGrant(client.grantTypes)) {
        return c.json({ error: 'unauthorized_client', error_description: 'Client is not authorized for the device authorization grant' }, 400)
      }
      const result = await exchangeDeviceCode(params.device_code, { clientId, clientType: client.clientType, authenticated: auth.authenticated }, ip, c.req.header('user-agent'))
      const response: Record<string, unknown> = {
        access_token: result.accessToken,
        ...(result.refreshToken ? { refresh_token: result.refreshToken } : {}),
        expires_in: result.expiresIn,
        token_type: 'Bearer',
        ...(result.scope ? { scope: result.scope } : {}),
      }
      if (result.scope?.split(/\s+/).includes('openid')) {
        response['id_token'] = await issueIdToken(result.userId, result.email, result.username, result.displayName, clientId, undefined, result.accessToken, {
          sessionId: result.sessionId, authTime: result.authTime, scope: result.scope,
        })
      }
      return c.json(response)
    } catch (err) {
      if (err instanceof ApiError) {
        return c.json({ error: err.code.toLowerCase(), error_description: err.message }, err.status as 400)
      }
      throw err
    }
  }

  // ── Handle token exchange (RFC 8693) ──
  if (params.grant_type === TOKEN_EXCHANGE_GRANT) {
    if (!clientId) return c.json({ error: 'invalid_request', error_description: 'client_id is required' }, 400)
    const auth = await authenticate(clientId)
    if (auth instanceof Response) return auth
    try {
      const client = await prisma.client.findUnique({ where: { id: clientId }, select: { clientType: true } })
      const result = await exchangeToken(
        { clientId, clientType: client?.clientType ?? 'public', authenticated: auth.authenticated },
        {
          subjectToken: params.subject_token,
          subjectTokenType: params.subject_token_type,
          audience: params.audience,
          resource: params.resource,
          scope: params.scope,
          requestedTokenType: params.requested_token_type,
          actorToken: params.actor_token,
        },
        ip,
      )
      return c.json({
        access_token: result.accessToken,
        issued_token_type: ACCESS_TOKEN_TYPE,
        token_type: 'Bearer',
        expires_in: result.expiresIn,
        scope: result.scope,
      })
    } catch (err) {
      if (err instanceof ApiError) return c.json({ error: err.code.toLowerCase(), error_description: err.message }, err.status as 400)
      throw err
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
        { sessionId: result.sessionId, authTime: result.authTime, scope: result.scope },
      )
      response['id_token'] = idToken
    }

    if (browserClientPolicies[clientId]) {
      await prisma.refreshToken.deleteMany({
        where: {
          tokenHash: sha256Hex(result.refreshToken),
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
    },
  })

  if (!user) {
    throw new ApiError(404, 'NOT_FOUND', 'User not found')
  }

  // OpenID Connect Core §5.4: `profile` and `email` select the standard claims. A token issued
  // without a scope (native sign-in) answers with all of them, as it always has.
  const scopes = principal.scope === undefined ? undefined : scopeTokens(principal.scope)
  const wants = (scope: string) => !scopes || scopes.includes(scope)
  c.header('Cache-Control', 'no-store')
  return c.json({
    sub: user.id,
    ...(wants('email') ? { email: user.email, email_verified: false } : {}),
    ...(wants('profile') ? { preferred_username: user.username, name: user.displayName } : {}),
    // Direct and group roles, as the user's tokens carry them.
    roles: (await userTokenGrants(user.id)).roles,
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
  return nativeDiscovery(c)
})

/** The native discovery document, also served at the issuer's own `.well-known` paths. */
export function nativeDiscovery(c: Context): Response {
  const configuration = getOpenIdConfiguration()
  if (!configuration) {
    c.header('Cache-Control', 'no-store')
    throw new ApiError(503, 'DISCOVERY_UNCONFIGURED', 'Set IAM_PUBLIC_URL to the public HTTPS URL of this server to publish discovery metadata')
  }
  // Built from configuration alone, so a short shared cache is safe; a URL change shows within minutes.
  c.header('Cache-Control', 'public, max-age=300')
  return c.json(configuration)
}

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
