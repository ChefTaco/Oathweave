/**
 * oauth-service.ts — OAuth2 Authorization Code Flow with PKCE.
 *
 * Implements RFC 6749 (OAuth 2.0) + RFC 7636 (PKCE).
 * Supports authorization code issuance, exchange, PKCE validation,
 * and OIDC-compatible discovery / userinfo / JWKS endpoints.
 */

import { validateBrowserAuthorization } from './browser-policies.js'
import { createHash, randomBytes } from 'node:crypto'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { discoveryMetadataUrl } from '../config/browser-discovery.js'
import { ID_TOKEN_CLAIMS } from './oidc-claims.js'
import { PROMPT_VALUES } from './authorization-prompt.js'
import { TOKEN_EXCHANGE_GRANT, tokenExchangeEnabled } from './token-exchange.js'
import { ApiError } from '../types/index.js'
import { getPublishedSigningJwks } from '../utils/keys.js'
import { issueTokenPair } from './token-service.js'
import { createSession, revokeSession } from './session-service.js'
import { parsePermissionList, userTokenGrants } from './effective-grants.js'
import { checkIpAllowlist } from '../utils/ip-allowlist.js'
import { logAuditEvent } from './audit-service.js'
import { assertClientAuthAllowed, recordClientAuthFailure, verifyClientSecret } from './client-auth-guard.js'

// ── Constants ──

/** Authorization codes expire after 10 minutes (RFC 6749 §4.1.2) */
const CODE_TTL_MS = 10 * 60 * 1000

// ── Types ──

export interface AuthorizeParams {
  clientId: string
  redirectUri: string
  responseType: string
  codeChallenge?: string | undefined
  codeChallengeMethod?: string | undefined
  scope?: string | undefined
  state?: string | undefined
  nonce?: string | undefined
  browserSessionId?: string | undefined
  /** The session the user approved from; its sign-in (or step-up) time becomes auth_time. */
  authSessionId?: string | undefined
}

export interface TokenExchangeParams {
  grantType: string
  code: string
  redirectUri: string
  clientId: string
  codeVerifier?: string | undefined
  /**
   * True only when the caller verified this client's secret for this request. A confidential
   * client's code is never exchanged without it.
   */
  clientAuthenticated?: boolean | undefined
}

export interface AuthorizeResult {
  code: string
  state?: string
  redirectUri: string
  /** True if client is first-party and consent can be skipped */
  skipConsent: boolean
  clientName: string
  scope?: string
}

// ── Authorization Code Issuance ──

/**
 * Validate an authorization request and generate an authorization code.
 * Called after the user has authenticated and consented.
 */
export async function createAuthorizationCode(
  userId: string,
  params: AuthorizeParams,
  ipAddress?: string,
): Promise<AuthorizeResult> {
  // Validate client
  const client = await prisma.client.findUnique({ where: { id: params.clientId } })
  if (!client || !client.active) {
    throw new ApiError(400, 'INVALID_CLIENT', 'Unknown or inactive client')
  }

  try { validateBrowserAuthorization(client, params) } catch { throw new ApiError(400, 'INVALID_REQUEST', 'Invalid registered redirect URI or S256 PKCE challenge') }

  // Validate response_type
  if (params.responseType !== 'code') {
    throw new ApiError(400, 'UNSUPPORTED_RESPONSE_TYPE', 'Only response_type=code is supported')
  }

  // Validate grant type
  const grantTypes: string[] = JSON.parse(client.grantTypes)
  if (!grantTypes.includes('authorization_code')) {
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for authorization_code grant')
  }

  // Validate redirect_uri against registered URIs
  // Non-first-party clients MUST have at least one registered redirect URI
  const registeredUris: string[] = JSON.parse(client.redirectUris)
  if (!client.firstParty && registeredUris.length === 0) {
    throw new ApiError(400, 'INVALID_CLIENT', 'Client has no registered redirect URIs')
  }
  if (registeredUris.length > 0 && !registeredUris.includes(params.redirectUri)) {
    throw new ApiError(400, 'INVALID_REDIRECT_URI', 'Redirect URI is not registered for this client')
  }

  // Validate PKCE: required for public clients
  if (client.clientType === 'public' && !params.codeChallenge) {
    throw new ApiError(400, 'INVALID_REQUEST', 'Public clients must use PKCE (code_challenge required)')
  }

  // Validate PKCE challenge method
  if (params.codeChallenge && params.codeChallengeMethod && params.codeChallengeMethod !== 'S256') {
    throw new ApiError(400, 'INVALID_REQUEST', 'Only S256 code_challenge_method is supported')
  }

  // Generate authorization code (cryptographically secure)
  const code = randomBytes(32).toString('base64url')
  const authSessionId = params.browserSessionId ?? params.authSessionId
  const authSession = authSessionId
    ? await prisma.session.findFirst({ where: { id: authSessionId, userId }, select: { createdAt: true, stepUpVerifiedAt: true } })
    : null

  await prisma.authorizationCode.create({
    data: {
      code,
      clientId: params.clientId,
      userId,
      redirectUri: params.redirectUri,
      scope: params.scope ?? null,
      codeChallenge: params.codeChallenge ?? null,
      state: params.state ?? null,
      nonce: params.nonce ?? null,
      browserSessionId: params.browserSessionId ?? null,
      authTime: authSession ? (authSession.stepUpVerifiedAt ?? authSession.createdAt) : null,
      expiresAt: new Date(Date.now() + CODE_TTL_MS),
    },
  })

  await logAuditEvent({
    eventType: 'oauth.authorize',
    category: 'AUTHENTICATION',
    actorId: userId,
    actorType: 'USER',
    ipAddress,
    action: 'oauth_authorize',
    outcome: 'SUCCESS',
    detail: { clientId: params.clientId, scope: params.scope },
    source: 'iam-api',
  })

  return {
    code,
    ...(params.state !== undefined ? { state: params.state } : {}),
    redirectUri: params.redirectUri,
    skipConsent: client.firstParty,
    clientName: client.name,
    ...(params.scope !== undefined ? { scope: params.scope } : {}),
  }
}

// ── Authorization Request Validation (pre-consent) ──

/**
 * Validate the authorize request parameters without creating a code.
 * Returns client info for the consent screen.
 */
export async function validateAuthorizeRequest(params: AuthorizeParams): Promise<{
  clientName: string
  clientDescription: string | null
  scope: string | undefined
  skipConsent: boolean
}> {
  const client = await prisma.client.findUnique({ where: { id: params.clientId } })
  if (!client || !client.active) {
    throw new ApiError(400, 'INVALID_CLIENT', 'Unknown or inactive client')
  }

  try { validateBrowserAuthorization(client, params) } catch { throw new ApiError(400, 'INVALID_REQUEST', 'Invalid registered redirect URI or S256 PKCE challenge') }

  if (params.responseType !== 'code') {
    throw new ApiError(400, 'UNSUPPORTED_RESPONSE_TYPE', 'Only response_type=code is supported')
  }

  const grantTypes: string[] = JSON.parse(client.grantTypes)
  if (!grantTypes.includes('authorization_code')) {
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for authorization_code grant')
  }

  const registeredUris: string[] = JSON.parse(client.redirectUris)
  if (!client.firstParty && registeredUris.length === 0) {
    throw new ApiError(400, 'INVALID_CLIENT', 'Client has no registered redirect URIs')
  }
  if (registeredUris.length > 0 && !registeredUris.includes(params.redirectUri)) {
    throw new ApiError(400, 'INVALID_REDIRECT_URI', 'Redirect URI is not registered for this client')
  }

  if (client.clientType === 'public' && !params.codeChallenge) {
    throw new ApiError(400, 'INVALID_REQUEST', 'Public clients must use PKCE (code_challenge required)')
  }

  if (params.codeChallenge && params.codeChallengeMethod && params.codeChallengeMethod !== 'S256') {
    throw new ApiError(400, 'INVALID_REQUEST', 'Only S256 code_challenge_method is supported')
  }

  return {
    clientName: client.name,
    clientDescription: client.description,
    scope: params.scope,
    skipConsent: client.firstParty,
  }
}

// ── Token Exchange ──

/** A client as the token endpoint knows it once its credentials have been checked. */
export interface TokenEndpointClient {
  clientType: string
  /** True when the request carried this client's secret and it verified. */
  authenticated: boolean
}

/**
 * Identify the client of a token request and check the credentials it presented.
 *
 * A confidential client must authenticate: without its secret the request is refused. A public
 * client has no secret; an authorization-code exchange binds it to its code by PKCE alone, which
 * `exchangeAuthorizationCode` requires. Every refusal is `invalid_client` (401) and counts as a
 * failed client authentication; an address over its failure ceiling is refused (429) before any
 * secret is verified.
 */
export async function authenticateTokenClient(
  clientId: string,
  presentedSecret: string | undefined,
  ipAddress: string,
): Promise<TokenEndpointClient> {
  await assertClientAuthAllowed(ipAddress, clientId)
  const refuse = async (message: string): Promise<never> => {
    await recordClientAuthFailure(ipAddress, clientId)
    throw new ApiError(401, 'INVALID_CLIENT', message)
  }
  const client = await prisma.client.findUnique({ where: { id: clientId } })
  if (!client || !client.active) return refuse('Unknown or inactive client')
  const confidential = client.clientType !== 'public'
  // A client's address allowlist applies to the token endpoint as it does to introspection.
  const allowed = (): void => {
    if (!checkIpAllowlist(parsePermissionList(client.allowedIps), ipAddress)) {
      throw new ApiError(401, 'INVALID_CLIENT', 'This client is not allowed from this address')
    }
  }
  if (presentedSecret === undefined || presentedSecret === '') {
    if (confidential) {
      return refuse('Client authentication required: this confidential client must send its client secret')
    }
    allowed()
    return { clientType: client.clientType, authenticated: false }
  }
  if (!client.secretHash) {
    return refuse(
      confidential
        ? 'This confidential client has no secret; set one before it uses the token endpoint'
        : 'Public clients cannot authenticate with a secret',
    )
  }
  if (!(await verifyClientSecret(ipAddress, clientId, client.secretHash, presentedSecret))) {
    throw new ApiError(401, 'INVALID_CLIENT', 'Invalid client secret')
  }
  allowed()
  return { clientType: client.clientType, authenticated: true }
}

/**
 * Exchange an authorization code for access + refresh tokens.
 *
 * Every exchange is bound to the client the code was issued to, so a stolen code alone is never
 * enough: a confidential client must have authenticated (`clientAuthenticated`), a public client
 * must have started the flow with an S256 PKCE challenge, and whenever the code carries a challenge
 * the matching `code_verifier` is required, for either client type.
 */
export async function exchangeAuthorizationCode(
  params: TokenExchangeParams,
  ipAddress?: string,
): Promise<{
  accessToken: string
  refreshToken: string
  expiresIn: number
  tokenType: string
  scope?: string
  userId?: string
  email?: string
  username?: string
  displayName?: string
  nonce?: string
  sessionId: string
  authTime?: Date
}> {
  if (params.grantType !== 'authorization_code') {
    throw new ApiError(400, 'UNSUPPORTED_GRANT_TYPE', 'Only authorization_code grant type is supported here')
  }

  // Find and validate the authorization code
  const authCode = await prisma.authorizationCode.findUnique({
    where: { code: params.code },
    include: {
      user: true,
      client: true,
    },
  })

  if (!authCode) {
    throw new ApiError(400, 'INVALID_GRANT', 'Authorization code is invalid')
  }

  // Code must not be expired
  if (authCode.expiresAt < new Date()) {
    // Clean up expired code
    await prisma.authorizationCode.delete({ where: { id: authCode.id } })
    throw new ApiError(400, 'INVALID_GRANT', 'Authorization code has expired')
  }

  // Validate client_id matches
  if (authCode.clientId !== params.clientId) {
    throw new ApiError(400, 'INVALID_GRANT', 'Client ID does not match the authorization code')
  }

  // Validate redirect_uri matches exactly
  if (authCode.redirectUri !== params.redirectUri) {
    throw new ApiError(400, 'INVALID_GRANT', 'Redirect URI does not match')
  }

  // Client binding. A confidential client proves itself with its secret; a public client has
  // none, so its code must carry the PKCE challenge it started the flow with.
  if (authCode.client.clientType !== 'public') {
    if (params.clientAuthenticated !== true) {
      throw new ApiError(401, 'INVALID_CLIENT', 'Client authentication required: this confidential client must send its client secret')
    }
  } else if (!authCode.codeChallenge) {
    throw new ApiError(400, 'INVALID_GRANT', 'Authorization code was issued to a public client without PKCE')
  }

  // Validate PKCE code_verifier
  if (authCode.codeChallenge) {
    if (!params.codeVerifier) {
      throw new ApiError(400, 'INVALID_GRANT', 'code_verifier required for PKCE-protected authorization')
    }

    const computedChallenge = createHash('sha256')
      .update(params.codeVerifier)
      .digest('base64url')

    if (computedChallenge !== authCode.codeChallenge) {
      throw new ApiError(400, 'INVALID_GRANT', 'PKCE code_verifier does not match code_challenge')
    }
  }

  // Code must not be already used (RFC 6749 §4.1.2: MUST invalidate after use). The replay is
  // judged only after it proved the client binding above, so a code copied from a log cannot be
  // used to sign anyone out: whoever replays it holds the client's secret or PKCE verifier, and
  // the tokens the first exchange issued are revoked with their session.
  if (authCode.usedAt) {
    await revokeReplayedCode(authCode, ipAddress)
    throw new ApiError(400, 'INVALID_GRANT', 'Authorization code has already been used')
  }

  if (!authCode.client.active) throw new ApiError(400, 'INVALID_GRANT', 'Client is inactive')
  if (authCode.browserSessionId) {
    const active = await prisma.session.findFirst({where:{id:authCode.browserSessionId,userId:authCode.userId,revokedAt:null,expiresAt:{gt:new Date()}}})
    if (!active) throw new ApiError(400, 'INVALID_GRANT', 'Browser session is inactive')
  }

  // Validate user is still active
  if (!authCode.user.active) {
    throw new ApiError(400, 'INVALID_GRANT', 'User account is inactive')
  }

  // The session is known before the code is consumed, so the consumption records it in the same
  // write and a replay can always find what to revoke.
  const createdSession = authCode.browserSessionId ? undefined : (await createSession(authCode.userId, ipAddress)).sessionId
  const sessionId = authCode.browserSessionId ?? createdSession!
  const consumed = await prisma.authorizationCode.updateMany({
    where: { id: authCode.id, usedAt:null, expiresAt:{gt:new Date()} },
    data: { usedAt: new Date(), issuedSessionId: sessionId },
  })
  if (consumed.count !== 1) {
    if (createdSession) await revokeSession(createdSession, 'code_exchange_race', { reason: 'code_exchange_race' })
    throw new ApiError(400, 'INVALID_GRANT', 'Authorization code has already been consumed')
  }

  // Issue tokens
  const { roles, permissions } = await userTokenGrants(authCode.userId)
  const tokenPair = await issueTokenPair(
    authCode.userId,
    authCode.user.email,
    authCode.user.username,
    roles,
    permissions,
    sessionId,
    ipAddress,
    authCode.clientId,
    undefined,
    undefined,
    authCode.scope ?? undefined,
  )

  await logAuditEvent({
    eventType: 'oauth.token_exchange',
    category: 'AUTHENTICATION',
    actorId: authCode.userId,
    actorType: 'USER',
    actorEmail: authCode.user.email,
    ipAddress,
    action: 'oauth_token_exchange',
    outcome: 'SUCCESS',
    detail: { clientId: authCode.clientId, scope: authCode.scope },
    source: 'iam-api',
  })

  return {
    accessToken: tokenPair.accessToken,
    refreshToken: tokenPair.refreshToken,
    expiresIn: tokenPair.expiresIn,
    tokenType: 'Bearer',
    ...(authCode.scope !== null ? { scope: authCode.scope } : {}),
    userId: authCode.userId,
    email: authCode.user.email,
    username: authCode.user.username,
    displayName: authCode.user.displayName,
    ...(authCode.nonce !== null ? { nonce: authCode.nonce } : {}),
    sessionId,
    ...(authCode.authTime ? { authTime: authCode.authTime } : {}),
  }
}

/**
 * An authorization code was exchanged again by its own client. Either that client or whoever
 * copied the code and its verifier is replaying it; the tokens the first exchange issued are
 * revoked with their session (RFC 6749 §4.1.2, RFC 9700 §4.2.4), and the attempt is audited.
 */
async function revokeReplayedCode(
  code: { id: string; userId: string; clientId: string; issuedSessionId: string | null },
  ipAddress?: string,
): Promise<void> {
  const revoked = code.issuedSessionId ? await revokeSession(code.issuedSessionId, 'code_replay', { reason: 'code_replay' }) : false
  await logAuditEvent({
    eventType: 'oauth.code_reuse',
    category: 'AUTHENTICATION',
    actorId: code.userId,
    actorType: 'USER',
    ipAddress,
    action: 'oauth_code_reuse_attempt',
    outcome: 'DENIED',
    detail: { clientId: code.clientId, codeId: code.id, sessionRevoked: revoked, ...(code.issuedSessionId ? { sessionId: code.issuedSessionId } : {}) },
    source: 'iam-api',
  })
}

// ── Client Credentials Grant ──

/**
 * Issue an access token for a confidential client using client_credentials grant.
 * No user context — the token represents the client itself.
 */
export async function exchangeClientCredentials(
  clientId: string,
  scope?: string,
  ipAddress?: string,
): Promise<{
  accessToken: string
  expiresIn: number
  tokenType: string
  scope?: string
}> {
  const client = await prisma.client.findUnique({ where: { id: clientId } })
  if (!client || !client.active) {
    throw new ApiError(400, 'INVALID_CLIENT', 'Unknown or inactive client')
  }

  if (client.clientType !== 'confidential') {
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Only confidential clients can use client_credentials grant')
  }

  const grantTypes: string[] = JSON.parse(client.grantTypes)
  if (!grantTypes.includes('client_credentials')) {
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for client_credentials grant')
  }

  const { issueClientCredentialsToken, lifetimeForClientCredentials, permissionsForClientCredentials } = await import('./token-service.js')
  const accessToken = await issueClientCredentialsToken(clientId, client.name, scope)
  // The response names the scope that was granted: the requested permissions this client may hold.
  const granted = permissionsForClientCredentials(clientId, scope).join(' ')

  await logAuditEvent({
    eventType: 'oauth.client_credentials',
    category: 'AUTHENTICATION',
    actorId: clientId,
    actorType: 'SERVICE_ACCOUNT',
    ipAddress,
    action: 'oauth_client_credentials',
    outcome: 'SUCCESS',
    detail: { clientId, scope },
    source: 'iam-api',
  })

  return {
    accessToken,
    expiresIn: lifetimeForClientCredentials(clientId),
    tokenType: 'Bearer',
    ...(granted ? { scope: granted } : {}),
  }
}

// ── OIDC Discovery ──

/**
 * Where native clients reach this server's `/api/v1` routes, from configuration only: request
 * `Host` and `X-Forwarded-*` headers never shape the metadata, so a cached document cannot be
 * poisoned. `IAM_PUBLIC_URL` (the URL `/api/v1` hangs off) wins, then `JWT_ISSUER` when it is an
 * HTTPS URL. The browser API base is not used: a suite ingress may expose only browser routes.
 */
export function nativeApiBaseUrl(): string | undefined {
  const usable = (value: string | undefined) => value !== undefined && discoveryMetadataUrl.safeParse(value).success
  const trim = (value: string) => value.replace(/\/+$/, '')
  if (usable(env.IAM_PUBLIC_URL)) return `${trim(env.IAM_PUBLIC_URL!)}/api/v1`
  if (usable(env.JWT_ISSUER)) return `${trim(env.JWT_ISSUER)}/api/v1`
  return undefined
}

/**
 * Return the native OpenID Connect Discovery document, or undefined when no public URL is
 * configured. `issuer` is `JWT_ISSUER`, the `iss` native tokens carry.
 */
export function getOpenIdConfiguration(): Record<string, unknown> | undefined {
  const api = nativeApiBaseUrl()
  if (!api) return undefined
  return {
    issuer: env.JWT_ISSUER,
    authorization_endpoint: `${api}/oauth/authorize`,
    token_endpoint: `${api}/oauth/token`,
    userinfo_endpoint: `${api}/oauth/userinfo`,
    jwks_uri: `${api}/oauth/jwks`,
    revocation_endpoint: `${api}/oauth/revoke`,
    introspection_endpoint: `${api}/oauth/introspect`,
    end_session_endpoint: `${api}/oauth/logout`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    ...(env.IAM_DEVICE_VERIFICATION_URL ? { device_authorization_endpoint: `${api}/oauth/device_authorization` } : {}),
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', ...(env.IAM_DEVICE_VERIFICATION_URL ? ['urn:ietf:params:oauth:grant-type:device_code'] : []), ...(tokenExchangeEnabled() ? [TOKEN_EXCHANGE_GRANT] : [])],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    revocation_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    introspection_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: [...ID_TOKEN_CLAIMS],
    prompt_values_supported: [...PROMPT_VALUES],
  }
}

// ── JWKS ──

/**
 * Convert the RS256 public key to JWK format for the JWKS endpoint.
 */
export async function getJwks(): Promise<{ keys: Record<string, unknown>[] }> {
  return getPublishedSigningJwks()
}

// ── Cleanup ──

/**
 * Delete expired authorization codes. Called periodically.
 */
export async function cleanupExpiredCodes(): Promise<number> {
  const result = await prisma.authorizationCode.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  })
  return result.count
}
