/**
 * Token introspection (RFC 7662) and revocation (RFC 7009) on behalf of an authenticated client.
 *
 * A client may introspect or revoke the tokens issued to it. Reaching other clients' tokens is an
 * explicit grant: `iam:tokens:introspect` or `iam:tokens:revoke` in the permissions the client may
 * hold (its machine client policy in IAM_MACHINE_CLIENT_POLICIES; the built-in `hive-router`
 * client holds `iam:tokens:introspect`). A token the caller may not see introspects as inactive,
 * so the answer does not reveal whether it exists.
 */
import { revokeSession } from './session-service.js'
import {
  clientCredentialsPermissionCeiling,
  findRefreshToken,
  revokeRefreshToken,
  verifyAccessToken,
  type AccessTokenPayload,
} from './token-service.js'

export const INTROSPECT_ANY_TOKEN = 'iam:tokens:introspect'
export const REVOKE_ANY_TOKEN = 'iam:tokens:revoke'

export interface TokenClientAuthority {
  readonly clientId: string
  readonly introspectAny: boolean
  readonly revokeAny: boolean
}

export function tokenClientAuthority(clientId: string): TokenClientAuthority {
  const ceiling = clientCredentialsPermissionCeiling(clientId)
  return {
    clientId,
    introspectAny: ceiling.includes(INTROSPECT_ANY_TOKEN),
    revokeAny: ceiling.includes(REVOKE_ANY_TOKEN),
  }
}

/** True when the access token was issued to this client (its authorization or its own credentials). */
function issuedTo(payload: AccessTokenPayload, clientId: string): boolean {
  return payload.clientId === clientId
}

async function verified(token: string): Promise<AccessTokenPayload | undefined> {
  try {
    return await verifyAccessToken(token)
  } catch {
    return undefined
  }
}

export type IntrospectionResponse = { active: false } | ({ active: true } & Record<string, unknown>)

export async function introspectForClient(authority: TokenClientAuthority, token: string): Promise<IntrospectionResponse> {
  const payload = await verified(token)
  if (!payload) return { active: false }
  if (!authority.introspectAny && !issuedTo(payload, authority.clientId)) return { active: false }
  const scope = typeof payload['scope'] === 'string' ? (payload['scope'] as string) : undefined
  return {
    active: true,
    // RFC 7662 §2.2 members.
    sub: payload.sub,
    ...(payload.clientId !== undefined ? { client_id: payload.clientId } : {}),
    token_type: 'Bearer',
    ...(scope !== undefined ? { scope } : {}),
    ...(payload.username !== undefined ? { username: payload.username } : {}),
    ...(payload.exp !== undefined ? { exp: payload.exp } : {}),
    ...(payload.iat !== undefined ? { iat: payload.iat } : {}),
    ...(payload.iss !== undefined ? { iss: payload.iss } : {}),
    ...(payload.aud !== undefined ? { aud: payload.aud } : {}),
    jti: payload.jti,
    // Oathweave members.
    ...(payload.email !== undefined ? { email: payload.email } : {}),
    roles: payload.roles,
    permissions: payload.permissions,
    ...(payload.sessionId !== undefined ? { session_id: payload.sessionId } : {}),
    actor_type: payload.actorType,
    // RFC 8693 §4.1: who acts for the subject of a delegated token.
    ...(payload['act'] !== undefined ? { act: payload['act'] } : {}),
  }
}

export type RevocationOutcome =
  | { outcome: 'revoked'; tokenType: 'access_token' | 'refresh_token'; subject: string; actorType: string }
  | { outcome: 'unknown' }
  | { outcome: 'forbidden' }

/**
 * Revoke an access token (its whole session; a session-less client_credentials token cannot be
 * recalled and simply expires) or a refresh token. An unknown or already invalid token is
 * `unknown`, which RFC 7009 answers with 200; another client's token is `forbidden`.
 */
export async function revokeForClient(
  authority: TokenClientAuthority,
  token: string,
  hint?: 'access_token' | 'refresh_token',
): Promise<RevocationOutcome> {
  // The hint orders the lookups; the other kind is still tried (RFC 7009 §2.1).
  const order = hint === 'refresh_token' ? [revokeRefresh, revokeAccess] : [revokeAccess, revokeRefresh]
  for (const attempt of order) {
    const result = await attempt(authority, token)
    if (result.outcome !== 'unknown') return result
  }
  return { outcome: 'unknown' }
}

async function revokeAccess(authority: TokenClientAuthority, token: string): Promise<RevocationOutcome> {
  const payload = await verified(token)
  if (!payload) return { outcome: 'unknown' }
  if (!authority.revokeAny && !issuedTo(payload, authority.clientId)) return { outcome: 'forbidden' }
  if (payload.sessionId) await revokeSession(payload.sessionId, `client:${authority.clientId}`, { reason: 'token_revocation' })
  return { outcome: 'revoked', tokenType: 'access_token', subject: payload.sub, actorType: payload.actorType }
}

async function revokeRefresh(authority: TokenClientAuthority, token: string): Promise<RevocationOutcome> {
  const stored = await findRefreshToken(token)
  if (!stored || stored.revokedAt || stored.expiresAt <= new Date()) return { outcome: 'unknown' }
  if (!authority.revokeAny && stored.clientId !== authority.clientId) return { outcome: 'forbidden' }
  await revokeRefreshToken(token)
  return { outcome: 'revoked', tokenType: 'refresh_token', subject: stored.userId, actorType: 'USER' }
}
