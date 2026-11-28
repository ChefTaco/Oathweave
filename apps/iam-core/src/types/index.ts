import type { ActorClaim } from '../services/actor-claim.js'
export type ActorType = 'USER' | 'SERVICE_ACCOUNT' | 'SYSTEM' | 'AGENT'

export interface Principal {
  readonly sub: string
  readonly actorType: ActorType
  readonly email: string | undefined
  readonly username: string | undefined
  readonly roles: readonly string[]
  readonly permissions: readonly string[]
  readonly sessionId: string | undefined
  readonly clientId: string | undefined
  /** OAuth scope of the access token, when it was issued for one (authorization code, refresh). */
  readonly scope?: string | undefined
  /** The `act` claim of a delegated (token-exchange) token: who acts for the subject. */
  readonly act?: ActorClaim | undefined
}

export interface HealthCheck {
  name: string
  status: 'pass' | 'fail'
  latencyMs?: number
  message?: string
}

export type AuditCategory =
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'USER_MANAGEMENT'
  | 'ROLE_MANAGEMENT'
  | 'GROUP_MANAGEMENT'
  | 'SERVICE_ACCOUNT'
  | 'SYSTEM_ACCESS'
  | 'TOKEN'
  | 'ADMIN'
  | 'SUDO'
  | 'AGENT'

export type AuditOutcome = 'SUCCESS' | 'FAILURE' | 'DENIED'

export interface TokenPair {
  accessToken: string
  refreshToken: string
  sessionId: string
  expiresIn: number
}

// Optional collection fields may be explicitly unavailable before queue JSON serialization.
export interface AuditEventInput {
  eventType: string
  category: AuditCategory
  actorId?: string | undefined
  actorType?: ActorType | undefined
  actorEmail?: string | undefined
  clientId?: string | undefined
  serviceAccountId?: string | undefined
  ipAddress?: string | undefined
  userAgent?: string | undefined
  resourceType?: string | undefined
  resourceId?: string | undefined
  action: string
  outcome?: AuditOutcome | undefined
  detail?: Record<string, unknown> | undefined
  source?: string | undefined
  hostName?: string | undefined
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}
