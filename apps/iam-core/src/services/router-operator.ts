// Side-effect free: the auth middleware loads it before any configuration-dependent module.
import type { Principal } from '../types/index.js'

export const ROUTER_PROXY_CLIENT_ID = 'hive-router'
export const MAX_OPERATOR_HEADER_BYTES = 2048

/** True only for the Router's own client-credentials token (subject and client are both the Router). */
export function isRouterProxyPrincipal(principal: Pick<Principal, 'sub' | 'clientId' | 'actorType'>): boolean {
  return principal.actorType === 'SERVICE_ACCOUNT' && principal.sub === ROUTER_PROXY_CLIENT_ID && principal.clientId === ROUTER_PROXY_CLIENT_ID
}

/**
 * True when the Router's `x-hive-operator` header names the console operator behind a request.
 * The Router's own token can manage IAM, so a write made with it must carry this attribution;
 * without it the token is read-only (see middleware/auth.ts). The Router sets the header from its
 * verified console session and strips any copy a caller sent.
 */
export function routerOperatorAttributed(raw: string | undefined): boolean {
  if (!raw || raw.length > MAX_OPERATOR_HEADER_BYTES) return false
  try {
    const value: unknown = JSON.parse(raw)
    if (!value || typeof value !== 'object') return false
    const id = (value as Record<string, unknown>)['id']
    return typeof id === 'string' && id.length > 0 && id.length <= 200
  } catch {
    return false
  }
}
