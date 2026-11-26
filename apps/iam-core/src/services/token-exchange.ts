/**
 * OAuth 2.0 Token Exchange (RFC 8693), first slice: delegation for people. A confidential suite
 * service that received a person's access token trades it for a short-lived token addressed to
 * one downstream service and narrowed to the permissions its policy lists there
 * (IAM_TOKEN_EXCHANGE_POLICIES, see token-exchange-policy.ts).
 *
 * The new token names the person (`sub`), the service acting for them (`act.sub`, RFC 8693
 * §4.1) and the person's session, so revoking that session revokes it too. It never outlives the
 * subject token and has no refresh token.
 */
import { nanoid } from 'nanoid'
import { SignJWT } from 'jose'
import { env } from '../config/env.js'
import { prisma } from '../db/client.js'
import { ApiError } from '../types/index.js'
import { getPrivateKey, getSigningKeyId } from '../utils/keys.js'
import { logAuditEvent } from './audit-service.js'
import { parsePermissionList, userTokenGrants } from './effective-grants.js'
import { parseTokenExchangePolicies } from './token-exchange-policy.js'
import { scopeTokens, verifyAccessToken } from './token-service.js'
import { issuerForClient } from './browser-policies.js'

export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'

export const tokenExchangePolicies = parseTokenExchangePolicies(process.env.IAM_TOKEN_EXCHANGE_POLICIES)

export function tokenExchangeEnabled(): boolean {
  return Object.keys(tokenExchangePolicies).length > 0
}

export interface TokenExchangeRequest {
  subjectToken: string | undefined
  subjectTokenType: string | undefined
  audience: string | undefined
  resource: string | undefined
  scope: string | undefined
  requestedTokenType: string | undefined
  actorToken: string | undefined
}

export interface TokenExchangeResult {
  accessToken: string
  expiresIn: number
  scope: string
}

function invalid(message: string): ApiError {
  return new ApiError(400, 'INVALID_REQUEST', message)
}

function audiences(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []
}

export async function exchangeToken(
  client: { clientId: string; clientType: string; authenticated: boolean },
  request: TokenExchangeRequest,
  ipAddress: string,
): Promise<TokenExchangeResult> {
  if (client.clientType === 'public' || !client.authenticated)
    throw new ApiError(401, 'INVALID_CLIENT', 'Token exchange requires an authenticated confidential client')
  const record = await prisma.client.findUnique({ where: { id: client.clientId }, select: { grantTypes: true } })
  const policy = Object.hasOwn(tokenExchangePolicies, client.clientId) ? tokenExchangePolicies[client.clientId] : undefined
  if (!record || !parsePermissionList(record.grantTypes).includes(TOKEN_EXCHANGE_GRANT) || !policy)
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for token exchange')

  if (!request.subjectToken) throw invalid('subject_token is required')
  if (request.subjectTokenType !== ACCESS_TOKEN_TYPE) throw invalid(`subject_token_type must be ${ACCESS_TOKEN_TYPE}`)
  if (request.requestedTokenType !== undefined && request.requestedTokenType !== ACCESS_TOKEN_TYPE)
    throw invalid(`Only ${ACCESS_TOKEN_TYPE} can be requested`)
  if (request.actorToken !== undefined) throw invalid('actor_token is not supported; the authenticated client is the actor')
  if (request.resource !== undefined) throw new ApiError(400, 'INVALID_TARGET', 'Name the target with audience, not resource')
  const audience = request.audience
  if (!audience) throw invalid('audience is required')
  const target = Object.hasOwn(policy.audiences, audience) ? policy.audiences[audience] : undefined
  if (!target) throw new ApiError(400, 'INVALID_TARGET', 'This client may not mint tokens for that audience')

  let subject: Awaited<ReturnType<typeof verifyAccessToken>>
  try {
    subject = await verifyAccessToken(request.subjectToken)
  } catch {
    throw new ApiError(400, 'INVALID_GRANT', 'subject_token is invalid, expired or revoked')
  }
  if (subject.actorType !== 'USER' || !subject.sessionId) throw new ApiError(400, 'INVALID_GRANT', 'subject_token must be a person\'s session token')
  // No chains: an exchanged token cannot be exchanged again.
  if (subject['act'] !== undefined) throw new ApiError(400, 'INVALID_GRANT', 'subject_token is already a delegated token')
  const addressedToCaller = subject.clientId === client.clientId || audiences(subject.aud).some((aud) => policy.subjectAudiences.includes(aud))
  if (!addressedToCaller) throw new ApiError(400, 'INVALID_GRANT', 'subject_token was not issued to this client')

  // The person's grants now, not the subject token's: a revoked role does not survive exchange.
  const { permissions: held } = await userTokenGrants(subject.sub)
  const wanted = request.scope === undefined ? target.permissions : scopeTokens(request.scope)
  const granted = wanted.filter((permission) => target.permissions.includes(permission) && (held.includes(permission) || held.includes('*')))
  if (granted.length === 0) throw new ApiError(400, 'INVALID_SCOPE', 'None of the requested permissions can be delegated')

  const now = Math.floor(Date.now() / 1000)
  const expiresAt = Math.min(now + target.lifetimeSeconds, typeof subject.exp === 'number' ? subject.exp : now + target.lifetimeSeconds)
  if (expiresAt <= now) throw new ApiError(400, 'INVALID_GRANT', 'subject_token has expired')
  const accessToken = await new SignJWT({
    actorType: 'USER',
    ...(subject.email !== undefined ? { email: subject.email } : {}),
    ...(subject.username !== undefined ? { username: subject.username } : {}),
    roles: [],
    permissions: granted,
    scope: granted.join(' '),
    sessionId: subject.sessionId,
    clientId: client.clientId,
    act: { sub: client.clientId },
  })
    .setProtectedHeader({ alg: 'RS256', kid: await getSigningKeyId() })
    .setSubject(subject.sub)
    .setIssuer(issuerForClient(client.clientId, env.JWT_ISSUER))
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .setJti(nanoid())
    .sign(await getPrivateKey())

  await logAuditEvent({
    eventType: 'oauth.token_exchange_delegated',
    category: 'TOKEN',
    actorId: subject.sub,
    actorType: 'USER',
    clientId: client.clientId,
    ipAddress,
    action: 'token_exchange',
    outcome: 'SUCCESS',
    detail: { audience, permissions: granted, sessionId: subject.sessionId },
    source: 'iam-api',
  })
  return { accessToken, expiresIn: expiresAt - now, scope: granted.join(' ') }
}
