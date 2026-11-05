import { SignJWT } from 'jose'
import { nanoid } from 'nanoid'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { ApiError, type Principal } from '../types/index.js'
import { issuerForClient } from './browser-policies.js'
import { getPrivateKey, getSigningKeyId } from '../utils/keys.js'
import { parsePermissionList } from './privilege-guard.js'

/** This is a server-owned delegation identity, never a public OAuth client.
 * It cannot authenticate to IAM mutation APIs, and never acquires refresh tokens. */
export async function enrollmentDelegation(principal: Principal, audience: 'emberpath' | 'hivemem', requested: readonly string[]): Promise<string> {
  if (principal.actorType !== 'USER' || !principal.sessionId) throw new ApiError(403, 'INTERACTIVE_SESSION_REQUIRED', 'Enrollment requires an interactive identity')
  const session = await prisma.session.findFirst({ where: { id: principal.sessionId, userId: principal.sub, revokedAt: null, expiresAt: { gt: new Date() }, user: { active: true } }, include: { user: { include: { roles: { include: { role: true } }, groupMemberships: { include: { group: { include: { roles: { include: { role: true } } } } } } } } } })
  if (!session) throw new ApiError(401, 'SESSION_REVOKED', 'Identity session is inactive')
  const grants = [...session.user.roles.map(item => item.role), ...session.user.groupMemberships.flatMap(item => item.group.roles.map(assignment => assignment.role))]
  const held = new Set(grants.flatMap(role => parsePermissionList(role.permissions)))
  const permissions = [...new Set(requested)]
  const ceiling = audience === 'emberpath' ? ['router:keys:write'] : permissions.filter(permission => permission.startsWith('hivemem:') && !permission.includes('*') && !permission.startsWith('hivemem:admin:all'))
  if (!permissions.length || permissions.some(permission => !ceiling.includes(permission) || !held.has(permission) && !(audience === 'hivemem' && held.has('hivemem:admin:all')))) throw new ApiError(403, 'PRODUCT_PERMISSION_REQUIRED', 'The operator must hold every delegated product permission or its product-admin grant')
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ actorType: 'USER', clientId: 'oathweave-enrollment', delegationVersion: 1, roles: [], permissions, sessionId: session.id, auth_time: Math.floor((session.stepUpVerifiedAt ?? session.createdAt).getTime() / 1000) })
    .setProtectedHeader({ alg: 'RS256', kid: await getSigningKeyId() }).setSubject(principal.sub).setIssuer(issuerForClient('oathweave-enrollment', env.JWT_ISSUER)).setAudience(audience).setIssuedAt(now).setExpirationTime(now + 60).setJti(nanoid()).sign(await getPrivateKey())
}
