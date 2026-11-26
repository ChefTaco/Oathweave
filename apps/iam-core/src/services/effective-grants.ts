import { prisma } from '../db/client.js'

/**
 * A user's effective grants: the roles assigned to the user directly plus the roles of every
 * group the user belongs to. Every place that turns a user into roles and permissions (sign-in,
 * MFA challenge, authorization-code exchange, refresh, the privilege guard) uses this one path,
 * so a group role grants exactly what a direct assignment of the same role grants.
 */

export interface RoleGrant {
  readonly name: string
  readonly permissions: string[]
}

export interface TokenGrants {
  readonly roles: string[]
  readonly permissions: string[]
}

export function parsePermissionList(value: unknown): string[] {
  let parsed: unknown = value
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value)
    } catch {
      return []
    }
  }
  return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === 'string') : []
}

const ROLE_FIELDS = { select: { name: true, permissions: true } } as const

function toGrants(rows: ReadonlyArray<{ role: { name: string; permissions: string } }>): RoleGrant[] {
  return rows.map((row) => ({ name: row.role.name, permissions: parsePermissionList(row.role.permissions) }))
}

/** Direct roles plus roles inherited from groups. */
export async function userEffectiveGrants(userId: string): Promise<RoleGrant[]> {
  const [direct, memberships] = await Promise.all([
    prisma.userRoleAssignment.findMany({ where: { userId }, include: { role: ROLE_FIELDS } }),
    prisma.groupMember.findMany({
      where: { userId },
      include: { group: { include: { roles: { include: { role: ROLE_FIELDS } } } } },
    }),
  ])
  return [...toGrants(direct), ...memberships.flatMap((membership) => toGrants(membership.group.roles))]
}

/** Role names and permissions as an access token carries them: deduplicated, first-seen order. */
export function tokenGrantsFrom(grants: readonly RoleGrant[]): TokenGrants {
  return {
    roles: [...new Set(grants.map((grant) => grant.name))],
    permissions: [...new Set(grants.flatMap((grant) => grant.permissions))],
  }
}

/** The roles and permissions a user's access token carries. */
export async function userTokenGrants(userId: string): Promise<TokenGrants> {
  return tokenGrantsFrom(await userEffectiveGrants(userId))
}
