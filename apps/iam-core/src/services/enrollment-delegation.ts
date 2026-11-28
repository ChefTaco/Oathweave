import { prisma } from '../db/client.js'
import { ApiError, type Principal } from '../types/index.js'
import { delegate, type DelegationTarget } from './token-exchange.js'
import { ENROLLMENT_ACTOR } from './token-exchange-policy.js'

type EnrollmentAudience = 'emberpath' | 'hivemem'

/**
 * The built-in token-exchange policy of the `oathweave-enrollment` actor: router keys for
 * Emberpath; explicit HiveMem permissions (never a wildcard or `admin:all`), which the operator
 * holds directly or through `hivemem:admin:all`. A `*` grant does not count. 60 seconds.
 */
const ENROLLMENT_TARGETS: Readonly<Record<EnrollmentAudience, DelegationTarget>> = {
  emberpath: {
    audience: 'emberpath',
    lifetimeSeconds: 60,
    offered: [],
    allows: (permission) => permission === 'router:keys:write',
    covered: (permission, held) => held.has(permission),
  },
  hivemem: {
    audience: 'hivemem',
    lifetimeSeconds: 60,
    offered: [],
    allows: (permission) => permission.startsWith('hivemem:') && !permission.includes('*') && !permission.startsWith('hivemem:admin:all'),
    covered: (permission, held) => held.has(permission) || held.has('hivemem:admin:all'),
  },
}

/**
 * A delegation for the operator's own session, minted by the token-exchange engine with the
 * server-owned `oathweave-enrollment` actor: `clientId` and `act.sub` are that actor,
 * `delegationVersion` is 1, the audience is exact, the lifetime 60 seconds, and the permissions
 * are exactly those requested, each of which the operator must still hold. This identity is
 * never a public OAuth client: it cannot authenticate to IAM mutation APIs and never acquires
 * refresh tokens.
 */
export async function enrollmentDelegation(principal: Principal, audience: EnrollmentAudience, requested: readonly string[]): Promise<string> {
  if (principal.actorType !== 'USER' || !principal.sessionId) throw new ApiError(403, 'INTERACTIVE_SESSION_REQUIRED', 'Enrollment requires an interactive identity')
  // No chains: a delegated token cannot delegate again.
  if (principal.act !== undefined) throw new ApiError(403, 'INTERACTIVE_SESSION_REQUIRED', 'Enrollment requires the operator\'s own session, not a delegated token')
  const session = await prisma.session.findFirst({
    where: { id: principal.sessionId, userId: principal.sub, revokedAt: null, expiresAt: { gt: new Date() }, user: { active: true } },
    select: { id: true, createdAt: true, stepUpVerifiedAt: true },
  })
  if (!session) throw new ApiError(401, 'SESSION_REVOKED', 'Identity session is inactive')
  const { accessToken } = await delegate({
    clientId: ENROLLMENT_ACTOR,
    act: { sub: ENROLLMENT_ACTOR },
    subject: {
      sub: principal.sub,
      sessionId: session.id,
      authTime: Math.floor((session.stepUpVerifiedAt ?? session.createdAt).getTime() / 1000),
    },
    target: ENROLLMENT_TARGETS[audience],
    requested,
    mode: 'exact',
    insufficient: () => new ApiError(403, 'PRODUCT_PERMISSION_REQUIRED', 'The operator must hold every delegated product permission or its product-admin grant'),
    identityClaims: false,
    scopeClaim: false,
    extraClaims: { delegationVersion: 1 },
    subjectTokenType: 'enrollment_session',
  })
  return accessToken
}
