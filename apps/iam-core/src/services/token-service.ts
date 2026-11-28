import { browserAccessLifetime, issuerForClient, browserClientPolicies, browserIssuedMachineClients, browserPermissions } from './browser-policies.js'
import { clientCredentialsPolicy } from './client-policies.js';
import { createLocalJWKSet, SignJWT, jwtVerify, type JWTPayload } from 'jose'
import { nanoid } from 'nanoid'
import { createHash } from 'node:crypto'
import { sha256Hex } from '@hivemagnus/hive-common/secrets'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import {
  getPrivateKey,
  getPublishedSigningJwks,
  getSigningKeyId,
} from '../utils/keys.js'
import { createSession, revokeSession } from '../services/session-service.js'
import { logAuditEvent } from './audit-service.js'
import { isActorClaim } from './actor-claim.js'
import { userTokenGrants } from './effective-grants.js'
import { REFRESH_RETRY_GRACE_SECONDS, RefreshGraceStore } from './refresh-grace.js'
import { ApiError } from '../types/index.js'
import type { TokenPair } from '../types/index.js'

export interface AccessTokenPayload extends JWTPayload {
  sub: string
  actorType: string
  email?: string
  username?: string
  roles: string[]
  permissions: string[]
  sessionId?: string
  clientId?: string
  jti: string
}

const hashToken = sha256Hex

/** Every permission a client_credentials token for this client could ever carry. */
export function clientCredentialsPermissionCeiling(clientId: string): string[] {
  return [...(clientCredentialsPolicy(clientId)?.permissions ?? [])]
}

export function permissionsForClientCredentials(clientId: string, scope?: string): string[] {
  if (!scope) return []
  const ceiling = new Set(clientCredentialsPolicy(clientId)?.permissions ?? [])
  return scope.split(/\s+/).map((entry) => entry.trim()).filter((permission) => permission && ceiling.has(permission))
}

export function audienceForClient(clientId?: string): string | undefined {
  if (clientId && browserClientPolicies[clientId]) return browserClientPolicies[clientId]!.audience
  return clientId ? clientCredentialsPolicy(clientId)?.audience : undefined
}

/**
 * `aud` of a person's access token. A client with a browser or machine client policy that names
 * an audience gets that audience, as before; a token issued to any other client (a relying
 * party's authorization code or device grant) is for that client alone, so it cannot be replayed
 * at a suite product. Native sign-in tokens (no client) carry no `aud`. Whether a token may call
 * Oathweave's own API is decided by its client in middleware/auth.ts, not by this claim.
 */
export function userAudienceForClient(clientId?: string): string | undefined {
  if (!clientId) return undefined
  return audienceForClient(clientId) ?? clientId
}

/** Native unless the client's machine policy selects the browser issuer. */
export function issuerForClientCredentials(clientId: string): string {
  return clientCredentialsPolicy(clientId)?.issuer === 'browser' ? issuerForClient(clientId, env.JWT_ISSUER) : env.JWT_ISSUER
}

export function lifetimeForClientCredentials(clientId: string): number {
  return Math.min(env.JWT_ACCESS_TTL, clientCredentialsPolicy(clientId)?.lifetimeSeconds ?? env.JWT_ACCESS_TTL)
}

export function clientCredentialsTokenProfile(
  clientId: string,
  clientName: string,
  scope?: string,
): {
  claims: Record<string, unknown>
  audience?: string
} {
  const audience = audienceForClient(clientId)
  return {
    claims: {
      actorType: 'SERVICE_ACCOUNT',
      clientId,
      clientName,
      token_type: 'access',
      scope,
      roles: [],
      permissions: permissionsForClientCredentials(clientId, scope),
    },
    ...(audience !== undefined ? { audience } : {}),
  }
}

export async function issueTokenPair(
  userId: string,
  email: string,
  username: string,
  roles: string[],
  permissions: string[],
  sessionId: string,
  ipAddress?: string,
  clientId?: string,
  userAgent?: string,
  /** The session's hard expiry: the refresh token never outlives it. */
  refreshNotAfter?: Date,
  /** The OAuth scope granted (authorization code, refresh); the tokens carry and keep it. */
  scope?: string,
): Promise<TokenPair> {
  const privateKey = await getPrivateKey()
  const signingKeyId = await getSigningKeyId()
  const now = Math.floor(Date.now() / 1000)

  const accessLifetime = browserAccessLifetime(clientId, env.JWT_ACCESS_TTL)
  const browserSession = clientId && browserClientPolicies[clientId]
    ? await prisma.session.findUnique({where:{id:sessionId},select:{createdAt:true,stepUpVerifiedAt:true}}) : null
  const authTime = browserSession ? Math.floor((browserSession.stepUpVerifiedAt ?? browserSession.createdAt).getTime()/1000) : undefined
  const token = new SignJWT({
    actorType: 'USER',
    ...(authTime !== undefined ? {auth_time:authTime} : {}),
    email,
    username,
    roles,
    permissions: clientId ? browserPermissions(clientId, permissions) : permissions,
    sessionId,
    ...(clientId ? { clientId } : {}),
    ...(scope ? { scope } : {}),
  })
    .setProtectedHeader({ alg: 'RS256', kid: signingKeyId })
    .setSubject(userId)
    .setIssuer(issuerForClient(clientId, env.JWT_ISSUER))
    .setIssuedAt(now)
    .setExpirationTime(now + accessLifetime)
    .setJti(nanoid())
  const audience = userAudienceForClient(clientId)
  if (audience) token.setAudience(audience)
  const accessToken = await token.sign(privateKey)

  const rawRefreshToken = nanoid(64)
  const refreshTokenHash = hashToken(rawRefreshToken)

  await prisma.refreshToken.create({
    data: {
      userId,
      sessionId,
      tokenHash: refreshTokenHash,
      ipAddress: ipAddress ?? null,
      clientId: clientId ?? null,
      scope: scope ?? null,
      userAgent: userAgent ?? null,
      expiresAt: new Date(
        Math.min(Date.now() + env.JWT_REFRESH_TTL * 1000, refreshNotAfter?.getTime() ?? Infinity),
      ),
    },
  })

  return {
    accessToken,
    refreshToken: rawRefreshToken,
    sessionId,
    expiresIn: accessLifetime,
  }
}

export async function issueServiceAccountToken(
  saId: string,
  clientId: string,
  roles: string[],
  permissions: string[],
): Promise<string> {
  const privateKey = await getPrivateKey()
  const signingKeyId = await getSigningKeyId()
  const now = Math.floor(Date.now() / 1000)

  return new SignJWT({
    actorType: 'SERVICE_ACCOUNT',
    clientId,
    roles,
    permissions,
  })
    .setProtectedHeader({ alg: 'RS256', kid: signingKeyId })
    .setSubject(saId)
    .setIssuer(env.JWT_ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + env.JWT_ACCESS_TTL)
    .setJti(nanoid())
    .sign(privateKey)
}

/**
 * Issue a client_credentials access token (no user context).
 */
export async function issueClientCredentialsToken(
  clientId: string,
  clientName: string,
  scope?: string,
): Promise<string> {
  const privateKey = await getPrivateKey()
  const signingKeyId = await getSigningKeyId()
  const now = Math.floor(Date.now() / 1000)
  const profile = clientCredentialsTokenProfile(clientId, clientName, scope)

  const token = new SignJWT(profile.claims)
    .setProtectedHeader({ alg: 'RS256', kid: signingKeyId })
    .setSubject(clientId)
    .setIssuer(issuerForClientCredentials(clientId))
    .setIssuedAt(now)
    .setExpirationTime(now + lifetimeForClientCredentials(clientId))
    .setJti(nanoid())
  if (profile.audience) {
    token.setAudience(profile.audience)
  }
  return token.sign(privateKey)
}

/** The space-separated tokens of an OAuth scope. */
export function scopeTokens(scope: string | null | undefined): string[] {
  return (scope ?? '').split(/\s+/).filter(Boolean)
}

export interface IdTokenContext {
  /** Session the tokens belong to: the `sid` claim, which RP-initiated logout ends. */
  sessionId?: string | undefined
  /** When the user last authenticated: the `auth_time` claim. */
  authTime?: Date | undefined
  /** Granted scope. Without it every standard claim is included, as before scopes were honoured. */
  scope?: string | undefined
}

/**
 * Issue an OIDC id_token: sub, aud, iss, iat, exp, auth_time, sid, nonce and at_hash, plus the
 * `profile` claims (preferred_username, name) and `email` claims (email, email_verified) the
 * granted scope asks for (OpenID Connect Core §5.4). Oathweave does not verify addresses, so
 * `email_verified` is false.
 */
export async function issueIdToken(
  userId: string,
  email: string,
  username: string,
  displayName: string,
  clientId: string,
  nonce?: string,
  accessToken?: string,
  context: IdTokenContext = {},
): Promise<string> {
  const privateKey = await getPrivateKey()
  const signingKeyId = await getSigningKeyId()
  const now = Math.floor(Date.now() / 1000)
  const scopes = context.scope === undefined ? undefined : scopeTokens(context.scope)

  const claims: Record<string, unknown> = {
    ...(!scopes || scopes.includes('profile') ? { preferred_username: username, name: displayName } : {}),
    ...(!scopes || scopes.includes('email') ? { email, email_verified: false } : {}),
  }
  if (context.authTime) claims['auth_time'] = Math.floor(context.authTime.getTime() / 1000)
  if (context.sessionId) claims['sid'] = context.sessionId

  if (nonce) claims['nonce'] = nonce

  // at_hash: left half of SHA-256 of the access token (RFC 3.1.3.6)
  if (accessToken) {
    const hash = createHash('sha256').update(accessToken).digest()
    claims['at_hash'] = hash.subarray(0, hash.length / 2).toString('base64url')
  }

  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: signingKeyId })
    .setSubject(userId)
    .setAudience(clientId)
    .setIssuer(issuerForClient(clientId, env.JWT_ISSUER))
    .setIssuedAt(now)
    .setExpirationTime(now + browserAccessLifetime(clientId, env.JWT_ACCESS_TTL))
    .setJti(nanoid())
    .sign(privateKey)
}

export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
  const verificationKeys = createLocalJWKSet(await getPublishedSigningJwks())
  try {
    const { payload } = await jwtVerify(token, verificationKeys, {
      issuer: [...new Set([env.JWT_ISSUER, ...[...Object.keys(browserClientPolicies), ...browserIssuedMachineClients()].map(id=>issuerForClient(id,env.JWT_ISSUER)), ...((process.env.IAM_ENROLLMENT_PRODUCTS_JSON || process.env.IAM_ENROLLMENT_INSTALLATIONS_JSON) ? [issuerForClient('oathweave-enrollment', env.JWT_ISSUER)] : [])])],
    })
    const access = payload as AccessTokenPayload
    if (payload.iss !== issuerForClient(access.clientId, env.JWT_ISSUER)) throw new Error('Access-token issuer does not match its client')
    if (access.clientId && browserClientPolicies[access.clientId] && payload.aud !== browserClientPolicies[access.clientId]!.audience) throw new Error('Invalid resource audience')
    if (access.clientId === 'oathweave-enrollment' && (payload.delegationVersion !== 1 || typeof payload.aud !== 'string' || !['emberpath','hivemem'].includes(payload.aud) || access.actorType !== 'USER' || !access.sessionId || !access.jti || typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || payload.exp <= payload.iat || payload.exp - payload.iat > 60)) throw new Error('Invalid enrollment delegation')
    // A delegated token's actor chain must be one Oathweave issues (token-exchange.ts).
    if (payload['act'] !== undefined && !isActorClaim(payload['act'])) throw new Error('Invalid actor claim')
    if (!access.sub || !access.actorType || !Array.isArray(access.roles) || !Array.isArray(access.permissions)) {
      throw new Error('Required access-token claims are missing')
    }
    if (access.sessionId) {
      const session = await prisma.session.findFirst({
        where: {
          id: access.sessionId,
          userId: access.sub,
          revokedAt: null,
          expiresAt: { gt: new Date() },
          user: { active: true },
        },
        select: { id: true },
      })
      if (!session) throw new Error('Access-token session is inactive or revoked')
    }
    return access
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Invalid token'
    throw new ApiError(401, 'INVALID_TOKEN', msg)
  }
}

export interface RefreshClientContext {
  /** True when the token request authenticated its client with the client's secret. */
  clientAuthenticated?: boolean
}

function invalidRefreshToken(message = 'Refresh token is invalid or expired'): ApiError {
  return new ApiError(401, 'INVALID_REFRESH_TOKEN', message)
}

/**
 * A refresh token that was already rotated or revoked was presented again. Either its rightful
 * client or whoever copied it is replaying it, and the server cannot tell which, so the session
 * (and with it every refresh token of the family) is revoked (RFC 9700 §4.14.2).
 */
async function revokeReplayedRefreshSession(
  token: { userId: string; sessionId: string | null; clientId: string | null },
  ipAddress?: string,
): Promise<void> {
  if (!token.sessionId) return
  const live = await prisma.session.findFirst({
    where: { id: token.sessionId, userId: token.userId, revokedAt: null },
    select: { id: true },
  })
  if (!live) return
  await revokeSession(token.sessionId, undefined, { reason: 'refresh_reuse' })
  await logAuditEvent({
    eventType: 'token.refresh_reuse',
    category: 'TOKEN',
    actorId: token.userId,
    actorType: 'USER',
    ipAddress,
    action: 'refresh_token_reuse',
    outcome: 'DENIED',
    detail: { sessionId: token.sessionId, clientId: token.clientId, sessionRevoked: true },
    source: 'iam-api',
  })
}

const refreshGrace = new RefreshGraceStore(async () => (await import('../queue/audit-queue.js')).redisConnection, env.REDIS_PREFIX)

type StoredRefreshToken = NonNullable<Awaited<ReturnType<typeof prisma.refreshToken.findUnique>>>

/**
 * Everything a refresh must pass besides the token being live: its client binding and client
 * authentication, its session, and its user. Returns the user and the session's hard expiry.
 */
async function assertRefreshAllowed(
  existing: StoredRefreshToken,
  clientId: string | undefined,
  context: RefreshClientContext,
  now: Date,
): Promise<{ user: { id: string; email: string; username: string }; sessionExpiresAt: Date | undefined }> {
  // Token binding: the clientId must match if the original token was bound.
  if (existing.clientId && existing.clientId !== clientId) {
    throw new ApiError(401, 'TOKEN_BINDING_MISMATCH', 'Refresh token was issued to a different client')
  }
  if (existing.clientId) {
    const client = await prisma.client.findUnique({
      where: { id: existing.clientId },
      select: { active: true, clientType: true, grantTypes: true },
    })
    if (!client || !client.active) throw new ApiError(401, 'INVALID_CLIENT', 'Unknown or inactive client')
    // RFC 6749 §6: a confidential client authenticates to refresh.
    if (client.clientType !== 'public' && context.clientAuthenticated !== true) {
      throw new ApiError(401, 'INVALID_CLIENT', 'Client authentication required: this confidential client must send its client secret')
    }
    if (!parseGrantTypes(client.grantTypes).includes('refresh_token')) {
      throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for the refresh_token grant')
    }
  }

  // A refresh token dies with its session. Paths that revoke only the session row
  // (administrator password resets, browser sign-out) must not leave a token that
  // keeps minting access tokens which offline verifiers still accept. Rotation never
  // extends a session past its hard expiry.
  let sessionExpiresAt: Date | undefined
  if (existing.sessionId) {
    const session = await prisma.session.findUnique({
      where: { id: existing.sessionId },
      select: { userId: true, revokedAt: true, expiresAt: true },
    })
    if (!session || session.userId !== existing.userId || session.revokedAt) {
      throw invalidRefreshToken('Refresh token session has been revoked')
    }
    if (session.expiresAt <= now) throw invalidRefreshToken('Refresh token session has expired')
    sessionExpiresAt = session.expiresAt
  }

  const user = await prisma.user.findUnique({
    where: { id: existing.userId },
    select: { id: true, email: true, username: true, active: true },
  })
  if (!user || !user.active) {
    throw new ApiError(401, 'USER_INACTIVE', 'User account is disabled')
  }
  return { user, sessionExpiresAt }
}

/**
 * A consumed token sent again inside the retry window gets the pair its rotation issued, provided
 * that successor is still unused and every refresh check still passes. Null when none of that
 * holds: the caller then treats the request as a replay.
 */
async function successorForRetry(
  rawToken: string,
  existing: StoredRefreshToken,
  clientId: string | undefined,
  context: RefreshClientContext,
  now: Date,
): Promise<TokenPair | null> {
  if (!existing.revokedAt || now.getTime() - existing.revokedAt.getTime() > REFRESH_RETRY_GRACE_SECONDS * 1000) return null
  const pair = await refreshGrace.recall(rawToken, now.getTime())
  if (!pair) return null
  const successor = await prisma.refreshToken.findUnique({
    where: { tokenHash: hashToken(pair.refreshToken) },
    select: { revokedAt: true, expiresAt: true },
  })
  // Once the successor has been used or revoked the client has moved on: this is a replay.
  if (!successor || successor.revokedAt || successor.expiresAt <= now) return null
  try {
    await assertRefreshAllowed(existing, clientId, context, now)
  } catch {
    return null
  }
  await logAuditEvent({
    eventType: 'token.refresh_retry',
    category: 'TOKEN',
    actorId: existing.userId,
    actorType: 'USER',
    action: 'refresh_token_retry',
    outcome: 'SUCCESS',
    detail: { sessionId: existing.sessionId, clientId: existing.clientId },
    source: 'iam-api',
  })
  return pair
}

export async function rotateRefreshToken(
  rawToken: string,
  ipAddress?: string,
  clientId?: string,
  userAgent?: string,
  context: RefreshClientContext = {},
): Promise<TokenPair> {
  const hash = hashToken(rawToken)
  const now = new Date()

  const existing = await prisma.refreshToken.findUnique({ where: { tokenHash: hash } })
  if (!existing) throw invalidRefreshToken()
  if (existing.revokedAt) {
    const retried = await successorForRetry(rawToken, existing, clientId, context, now)
    if (retried) return retried
    await revokeReplayedRefreshSession(existing, ipAddress)
    throw invalidRefreshToken()
  }
  if (existing.expiresAt <= now) throw invalidRefreshToken()

  // Every check runs before the token is consumed, so a request that fails one of them (another
  // client's id, a missing client secret) does not burn the rightful holder's token.
  const { user, sessionExpiresAt } = await assertRefreshAllowed(existing, clientId, context, now)

  // Atomic consumption: only one request can rotate a given token (prevents TOCTOU races).
  const consumed = await prisma.refreshToken.updateMany({
    where: { tokenHash: hash, revokedAt: null, expiresAt: { gt: now } },
    data: { revokedAt: now },
  })
  if (consumed.count === 0) {
    // A concurrent request rotated it first: answer with that request's successor once it exists.
    for (let attempt = 0; attempt < 20; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 100))
      const current = await prisma.refreshToken.findUnique({ where: { tokenHash: hash } })
      const retried = current && (await successorForRetry(rawToken, current, clientId, context, new Date()))
      if (retried) return retried
    }
    throw invalidRefreshToken()
  }

  const { roles, permissions } = await userTokenGrants(user.id)

  // Ensure we have a valid session — create one if orphaned
  let sessionId = existing.sessionId
  if (!sessionId) {
    const result = await createSession(user.id, ipAddress)
    sessionId = result.sessionId
  }

  const pair = await issueTokenPair(
    user.id,
    user.email,
    user.username,
    roles,
    permissions,
    sessionId,
    ipAddress,
    // The binding recorded at issuance decides the client. A token that was not
    // issued to a client never takes one from the request: the caller would
    // otherwise choose the clientId, audience and issuer of the new access token.
    existing.clientId ?? undefined,
    userAgent,
    sessionExpiresAt,
    existing.scope ?? undefined,
  )
  await refreshGrace.remember(rawToken, pair, now.getTime())
  return pair
}

function parseGrantTypes(value: unknown): string[] {
  try {
    const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value
    return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === 'string') : []
  } catch {
    return []
  }
}

/**
 * Revoke a refresh token. `owner` narrows it to a token of that user or client, so a caller can
 * only revoke what is theirs; the count says whether a live token matched.
 */
export async function revokeRefreshToken(
  rawToken: string,
  owner: { userId?: string; clientId?: string } = {},
): Promise<number> {
  const hash = hashToken(rawToken)
  const result = await prisma.refreshToken.updateMany({
    where: {
      tokenHash: hash,
      revokedAt: null,
      ...(owner.userId !== undefined ? { userId: owner.userId } : {}),
      ...(owner.clientId !== undefined ? { clientId: owner.clientId } : {}),
    },
    data: { revokedAt: new Date() },
  })
  return result.count
}

/** The stored binding of a refresh token, without consuming it. */
export async function findRefreshToken(rawToken: string): Promise<{ userId: string; clientId: string | null; sessionId: string | null; revokedAt: Date | null; expiresAt: Date } | null> {
  return prisma.refreshToken.findUnique({
    where: { tokenHash: hashToken(rawToken) },
    select: { userId: true, clientId: true, sessionId: true, revokedAt: true, expiresAt: true },
  })
}
