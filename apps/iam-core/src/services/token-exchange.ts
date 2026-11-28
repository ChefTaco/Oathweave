/**
 * OAuth 2.0 Token Exchange (RFC 8693): delegation for people. A confidential suite service that
 * holds a person's token trades it for a short-lived token addressed to one downstream service
 * and narrowed to the permissions its policy lists there (IAM_TOKEN_EXCHANGE_POLICIES, see
 * token-exchange-policy.ts).
 *
 * The new token names the person (`sub`), the party acting for them (`act`, RFC 8693 §4.1) and
 * the person's session, so revoking that session revokes it too. By default the authenticated
 * client is the actor (`act.sub`). With an `actor_token` (a machine client's client_credentials
 * token, allowed by the policy for that audience) the named client is the current actor and the
 * caller the prior one (`act.act.sub`). The token never outlives the subject or actor token,
 * never carries more than the policy allows or the person still holds, has no refresh token and
 * cannot be exchanged again. Every exchange, granted or refused, is audited.
 *
 * The subject is a person's access token, or (when the policy opts in) a refresh token issued to
 * the calling client. ID tokens and other types are refused; see REFUSED_SUBJECT_TOKEN_TYPES.
 *
 * `delegate()` is the engine. Identity enrollment (enrollment-delegation.ts) uses it with a
 * built-in policy for the server-owned `oathweave-enrollment` actor.
 */
import { nanoid } from 'nanoid'
import { SignJWT } from 'jose'
import { env } from '../config/env.js'
import { prisma } from '../db/client.js'
import { ApiError } from '../types/index.js'
import { getPrivateKey, getSigningKeyId } from '../utils/keys.js'
import { logAuditEvent } from './audit-service.js'
import type { ActorClaim } from './actor-claim.js'
import { parsePermissionList, userTokenGrants } from './effective-grants.js'
import { parseTokenExchangePolicies, type SubjectTokenTypeName, type TokenExchangePolicy } from './token-exchange-policy.js'
import { findRefreshToken, scopeTokens, verifyAccessToken, type AccessTokenPayload } from './token-service.js'
import { issuerForClient } from './browser-policies.js'

export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
const TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:'
export const ACCESS_TOKEN_TYPE = `${TOKEN_TYPE}access_token`
export const REFRESH_TOKEN_TYPE = `${TOKEN_TYPE}refresh_token`
export const ID_TOKEN_TYPE = `${TOKEN_TYPE}id_token`

/** Subject token types RFC 8693 defines that Oathweave never exchanges, and why. */
export const REFUSED_SUBJECT_TOKEN_TYPES: Readonly<Record<string, string>> = Object.freeze({
  [ID_TOKEN_TYPE]:
    'id_token is refused as subject_token: an ID token proves a sign-in to its client, travels in browser URLs (id_token_hint) and logs, and carries none of the person\'s authority; exchange the access or refresh token instead',
  [`${TOKEN_TYPE}jwt`]: 'jwt is refused as subject_token: name the Oathweave token by its type (access_token or refresh_token)',
  [`${TOKEN_TYPE}saml1`]: 'SAML assertions are refused as subject_token: Oathweave exchanges only the tokens it issued',
  [`${TOKEN_TYPE}saml2`]: 'SAML assertions are refused as subject_token: Oathweave exchanges only the tokens it issued',
})

const SUBJECT_TOKEN_TYPES: Readonly<Record<string, SubjectTokenTypeName>> = {
  [ACCESS_TOKEN_TYPE]: 'access_token',
  [REFRESH_TOKEN_TYPE]: 'refresh_token',
}

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
  actorTokenType?: string | undefined
}

export interface TokenExchangeResult {
  accessToken: string
  expiresIn: number
  scope: string
}

/**
 * RFC 8693 §2.2.2: a subject or actor token that is invalid or unacceptable under the policy is
 * `invalid_request` (not `invalid_grant`), as is any other malformed request.
 */
function invalid(message: string): ApiError {
  return new ApiError(400, 'INVALID_REQUEST', message)
}


function audiences(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []
}

// ── The engine ──

/** The person a delegated token is for. */
export interface DelegationSubject {
  readonly sub: string
  readonly sessionId: string
  readonly email?: string | undefined
  readonly username?: string | undefined
  /** `auth_time` to carry, epoch seconds. */
  readonly authTime?: number | undefined
  /** Epoch seconds the delegated token must not outlive (the subject or actor token's expiry). */
  readonly notAfter?: number | undefined
  /** Which presented token `notAfter` comes from, for the refusal when it has passed. */
  readonly notAfterSource?: 'subject_token' | 'actor_token' | undefined
}

/** One downstream audience of a policy: what may be delegated to it, and for how long. */
export interface DelegationTarget {
  readonly audience: string
  readonly lifetimeSeconds: number
  /** What a request that names no permissions asks for. */
  readonly offered: readonly string[]
  /** The policy ceiling: may this permission be delegated to the audience at all? */
  allows(permission: string): boolean
  /** Does the person's current grant cover this permission? */
  covered(permission: string, held: ReadonlySet<string>): boolean
}

export interface DelegationRequest {
  /** The `clientId` claim: the client the token is issued to. */
  readonly clientId: string
  /** The `act` claim. */
  readonly act: ActorClaim
  readonly subject: DelegationSubject
  readonly target: DelegationTarget
  /** Requested permissions; undefined asks for everything the policy allows. */
  readonly requested?: readonly string[] | undefined
  /**
   * `narrow` grants what can be delegated and refuses only when that is nothing; `exact` refuses
   * unless every requested permission can be. Both refuse with `insufficient`.
   */
  readonly mode: 'narrow' | 'exact'
  readonly insufficient: () => ApiError
  /** Claim profile: email/username and `scope` (exchange), or neither plus `extraClaims` (enrollment). */
  readonly identityClaims: boolean
  readonly scopeClaim: boolean
  readonly extraClaims?: Readonly<Record<string, unknown>>
  /** For the audit record. */
  readonly subjectTokenType: string
  readonly ipAddress?: string | undefined
}

export interface Delegation {
  readonly accessToken: string
  readonly expiresIn: number
  readonly permissions: string[]
}

/**
 * Mint a delegated token. The permissions are the requested ones the target allows and the
 * person holds now (not what any presented token says, so a revoked role does not survive
 * exchange); the lifetime is the target's, cut to the subject's `notAfter`.
 */
export async function delegate(request: DelegationRequest): Promise<Delegation> {
  const { subject, target } = request
  const { permissions: heldList } = await userTokenGrants(subject.sub)
  const held = new Set(heldList)
  const wanted = [...new Set(request.requested ?? target.offered)]
  const granted = wanted.filter((permission) => target.allows(permission) && target.covered(permission, held))
  if (granted.length === 0 || (request.mode === 'exact' && granted.length !== wanted.length)) throw request.insufficient()

  const now = Math.floor(Date.now() / 1000)
  const expiresAt = Math.min(now + target.lifetimeSeconds, subject.notAfter ?? Number.POSITIVE_INFINITY)
  if (expiresAt <= now) throw invalid(`${subject.notAfterSource ?? 'subject_token'} has expired`)
  const accessToken = await new SignJWT({
    actorType: 'USER',
    ...(request.identityClaims && subject.email !== undefined ? { email: subject.email } : {}),
    ...(request.identityClaims && subject.username !== undefined ? { username: subject.username } : {}),
    ...request.extraClaims,
    roles: [],
    permissions: granted,
    ...(request.scopeClaim ? { scope: granted.join(' ') } : {}),
    sessionId: subject.sessionId,
    ...(subject.authTime !== undefined ? { auth_time: subject.authTime } : {}),
    clientId: request.clientId,
    act: request.act,
  })
    .setProtectedHeader({ alg: 'RS256', kid: await getSigningKeyId() })
    .setSubject(subject.sub)
    .setIssuer(issuerForClient(request.clientId, env.JWT_ISSUER))
    .setAudience(target.audience)
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .setJti(nanoid())
    .sign(await getPrivateKey())

  await logAuditEvent({
    eventType: 'oauth.token_exchange_delegated',
    category: 'TOKEN',
    actorId: subject.sub,
    actorType: 'USER',
    clientId: request.clientId,
    ipAddress: request.ipAddress,
    action: 'token_exchange',
    outcome: 'SUCCESS',
    detail: {
      audience: target.audience,
      permissions: granted,
      sessionId: subject.sessionId,
      subjectTokenType: request.subjectTokenType,
      act: request.act,
      expiresIn: expiresAt - now,
    },
    source: 'iam-api',
  })
  return { accessToken, expiresIn: expiresAt - now, permissions: granted }
}

/** A target from IAM_TOKEN_EXCHANGE_POLICIES. A person holding `*` holds every permission. */
function configuredTarget(audience: string, entry: TokenExchangePolicy['audiences'][string]): DelegationTarget {
  return {
    audience,
    lifetimeSeconds: entry.lifetimeSeconds,
    offered: entry.permissions,
    allows: (permission) => entry.permissions.includes(permission),
    covered: (permission, held) => held.has(permission) || held.has('*'),
  }
}

// ── RFC 8693 at the token endpoint ──

interface Caller {
  clientId: string
  clientType: string
  authenticated: boolean
}

/** A presented token addressed to the caller: issued to it, or for one of its subject audiences. */
function addressedTo(token: AccessTokenPayload, caller: string, policy: TokenExchangePolicy): boolean {
  return token.clientId === caller || audiences(token.aud).some((aud) => policy.subjectAudiences.includes(aud))
}

async function accessTokenSubject(raw: string, caller: string, policy: TokenExchangePolicy): Promise<DelegationSubject> {
  let subject: AccessTokenPayload
  try {
    subject = await verifyAccessToken(raw)
  } catch {
    throw invalid('subject_token is invalid, expired or revoked')
  }
  if (subject.actorType !== 'USER' || !subject.sessionId) throw invalid('subject_token must be a person\'s session token')
  // No chains: an exchanged token cannot be exchanged again.
  if (subject['act'] !== undefined) throw invalid('subject_token is already a delegated token')
  if (!addressedTo(subject, caller, policy)) throw invalid('subject_token was not issued to this client')
  return {
    sub: subject.sub,
    sessionId: subject.sessionId,
    email: subject.email,
    username: subject.username,
    notAfter: typeof subject.exp === 'number' ? subject.exp : undefined,
  }
}

/**
 * A person's refresh token, looked up without consuming it. It must be live and issued to the
 * caller itself (refresh tokens are bound to one client, so `subjectAudiences` does not apply),
 * and its session and user must be active. A rotated token is refused but does not end the
 * session: the caller authenticated, and refresh-token reuse detection stays with the refresh
 * grant.
 */
async function refreshTokenSubject(raw: string, caller: string): Promise<DelegationSubject> {
  const now = new Date()
  const stored = await findRefreshToken(raw)
  if (!stored || stored.revokedAt || stored.expiresAt <= now) throw invalid('subject_token is invalid, expired or revoked')
  if (stored.clientId !== caller) throw invalid('subject_token was not issued to this client')
  if (!stored.sessionId) throw invalid('subject_token must be a person\'s session token')
  const session = await prisma.session.findFirst({
    where: { id: stored.sessionId, userId: stored.userId, revokedAt: null, expiresAt: { gt: now }, user: { active: true } },
    select: { expiresAt: true, user: { select: { email: true, username: true } } },
  })
  if (!session) throw invalid('subject_token is invalid, expired or revoked')
  return {
    sub: stored.userId,
    sessionId: stored.sessionId,
    email: session.user.email,
    username: session.user.username,
    notAfter: Math.floor(Math.min(stored.expiresAt.getTime(), session.expiresAt.getTime()) / 1000),
  }
}

/**
 * The `act` claim, and the actor token's expiry. Without an actor token the caller acts. An
 * actor token must be a live client_credentials token of an active machine client that is the
 * caller itself, or that the policy lists in `actors` for this audience and whose token is
 * addressed to the caller. People are never actors: one person acting for another is not
 * delegation this endpoint grants.
 */
async function resolveActor(
  caller: string,
  policy: TokenExchangePolicy,
  entry: TokenExchangePolicy['audiences'][string],
  request: TokenExchangeRequest,
): Promise<{ act: ActorClaim; notAfter?: number | undefined }> {
  if (request.actorToken === undefined) {
    if (request.actorTokenType !== undefined) throw invalid('actor_token_type is sent only with actor_token')
    return { act: { sub: caller } }
  }
  if (request.actorTokenType !== ACCESS_TOKEN_TYPE) throw invalid(`actor_token_type must be ${ACCESS_TOKEN_TYPE}`)
  let actor: AccessTokenPayload
  try {
    actor = await verifyAccessToken(request.actorToken)
  } catch {
    throw invalid('actor_token is invalid, expired or revoked')
  }
  if (actor['act'] !== undefined) throw invalid('actor_token is already a delegated token')
  if (actor.actorType !== 'SERVICE_ACCOUNT' || actor.sessionId !== undefined || !actor.clientId || actor.clientId !== actor.sub)
    throw invalid('actor_token must be a client_credentials token of a machine client; a person is never the actor')
  const notAfter = typeof actor.exp === 'number' ? actor.exp : undefined
  if (actor.sub === caller) return { act: { sub: caller }, notAfter }
  if (!entry.actors.includes(actor.sub)) throw invalid('This client may not name that actor for this audience')
  if (!addressedTo(actor, caller, policy)) throw invalid('actor_token was not issued to this client')
  const client = await prisma.client.findUnique({ where: { id: actor.sub }, select: { active: true } })
  if (!client?.active) throw invalid('actor_token is invalid, expired or revoked')
  return { act: { sub: actor.sub, act: { sub: caller } }, notAfter }
}

async function exchange(client: Caller, request: TokenExchangeRequest, ipAddress: string): Promise<TokenExchangeResult> {
  const record = await prisma.client.findUnique({ where: { id: client.clientId }, select: { grantTypes: true } })
  const policy = Object.hasOwn(tokenExchangePolicies, client.clientId) ? tokenExchangePolicies[client.clientId] : undefined
  if (!record || !parsePermissionList(record.grantTypes).includes(TOKEN_EXCHANGE_GRANT) || !policy)
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for token exchange')

  if (!request.subjectToken) throw invalid('subject_token is required')
  const refusedType = request.subjectTokenType !== undefined && Object.hasOwn(REFUSED_SUBJECT_TOKEN_TYPES, request.subjectTokenType)
    ? REFUSED_SUBJECT_TOKEN_TYPES[request.subjectTokenType] : undefined
  if (refusedType) throw invalid(refusedType)
  const subjectType = request.subjectTokenType !== undefined && Object.hasOwn(SUBJECT_TOKEN_TYPES, request.subjectTokenType)
    ? SUBJECT_TOKEN_TYPES[request.subjectTokenType] : undefined
  if (!subjectType) throw invalid(`subject_token_type must be ${ACCESS_TOKEN_TYPE} or ${REFRESH_TOKEN_TYPE}`)
  if (!policy.subjectTokenTypes.includes(subjectType))
    throw invalid(`This client may not exchange a ${subjectType}; its policy accepts ${policy.subjectTokenTypes.join(', ')}`)
  if (request.requestedTokenType !== undefined && request.requestedTokenType !== ACCESS_TOKEN_TYPE)
    throw invalid(`Only ${ACCESS_TOKEN_TYPE} can be requested: a delegated token never comes with a refresh token`)
  if (request.resource !== undefined) throw new ApiError(400, 'INVALID_TARGET', 'Name the target with audience, not resource')
  const audience = request.audience
  if (!audience) throw invalid('audience is required')
  const entry = Object.hasOwn(policy.audiences, audience) ? policy.audiences[audience] : undefined
  if (!entry) throw new ApiError(400, 'INVALID_TARGET', 'This client may not mint tokens for that audience')

  const subject = subjectType === 'access_token'
    ? await accessTokenSubject(request.subjectToken, client.clientId, policy)
    : await refreshTokenSubject(request.subjectToken, client.clientId)
  const actor = await resolveActor(client.clientId, policy, entry, request)
  const subjectEnd = subject.notAfter ?? Number.POSITIVE_INFINITY
  const actorEnd = actor.notAfter ?? Number.POSITIVE_INFINITY
  const notAfter = Math.min(subjectEnd, actorEnd)

  const result = await delegate({
    clientId: client.clientId,
    act: actor.act,
    subject: {
      ...subject,
      notAfter: Number.isFinite(notAfter) ? notAfter : undefined,
      notAfterSource: actorEnd < subjectEnd ? 'actor_token' : 'subject_token',
    },
    target: configuredTarget(audience, entry),
    requested: request.scope === undefined ? undefined : scopeTokens(request.scope),
    mode: 'narrow',
    insufficient: () => new ApiError(400, 'INVALID_SCOPE', 'None of the requested permissions can be delegated'),
    identityClaims: true,
    scopeClaim: true,
    subjectTokenType: subjectType,
    ipAddress,
  })
  return { accessToken: result.accessToken, expiresIn: result.expiresIn, scope: result.permissions.join(' ') }
}

/** Longest caller-supplied value copied into a refusal's audit record. */
const AUDIT_VALUE_MAX = 200

export async function exchangeToken(client: Caller, request: TokenExchangeRequest, ipAddress: string): Promise<TokenExchangeResult> {
  if (client.clientType === 'public' || !client.authenticated)
    throw new ApiError(401, 'INVALID_CLIENT', 'Token exchange requires an authenticated confidential client')
  try {
    return await exchange(client, request, ipAddress)
  } catch (error) {
    if (error instanceof ApiError) {
      // Refusals of an authenticated client are audited too; never with a token, only its type.
      await logAuditEvent({
        eventType: 'oauth.token_exchange_refused',
        category: 'TOKEN',
        clientId: client.clientId,
        ipAddress,
        action: 'token_exchange',
        outcome: 'DENIED',
        detail: {
          error: error.code.toLowerCase(),
          reason: error.message,
          ...(request.audience !== undefined ? { audience: request.audience.slice(0, AUDIT_VALUE_MAX) } : {}),
          ...(request.subjectTokenType !== undefined ? { subjectTokenType: request.subjectTokenType.slice(0, AUDIT_VALUE_MAX) } : {}),
          actorToken: request.actorToken !== undefined,
        },
        source: 'iam-api',
      })
    }
    throw error
  }
}
