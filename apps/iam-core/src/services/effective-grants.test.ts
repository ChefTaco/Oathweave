import { describe, expect, it, vi } from 'vitest'

const rows = vi.hoisted(() => ({
  direct: [] as { role: { name: string; permissions: string } }[],
  groups: [] as { group: { roles: { role: { name: string; permissions: string } }[] } }[],
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    userRoleAssignment: { findMany: vi.fn(async () => rows.direct) },
    groupMember: { findMany: vi.fn(async () => rows.groups) },
  },
}))

const { userTokenGrants } = await import('./effective-grants.js')
const { getEffectivePermissions } = await import('./group-service.js')

const role = (name: string, permissions: unknown) => ({ role: { name, permissions: JSON.stringify(permissions) } })

describe('effective grants', () => {
  it('joins direct roles with the roles of every group, without duplicates', async () => {
    rows.direct = [role('VIEWER', ['example:read'])]
    rows.groups = [
      { group: { roles: [role('OPERATOR', ['example:read', 'example:deploy'])] } },
      { group: { roles: [role('VIEWER', ['example:read']), role('AUDITOR', ['iam:audit:read'])] } },
    ]
    expect(await userTokenGrants('fixture-user')).toEqual({
      roles: ['VIEWER', 'OPERATOR', 'AUDITOR'],
      permissions: ['example:read', 'example:deploy', 'iam:audit:read'],
    })
    expect(await getEffectivePermissions('fixture-user')).toEqual(['example:read', 'example:deploy', 'iam:audit:read'])
  })

  it('grants through a group alone', async () => {
    rows.direct = []
    rows.groups = [{ group: { roles: [role('OPERATOR', ['example:deploy'])] } }]
    expect(await userTokenGrants('fixture-user')).toEqual({ roles: ['OPERATOR'], permissions: ['example:deploy'] })
  })

  it('ignores a malformed permission list', async () => {
    rows.direct = [{ role: { name: 'BROKEN', permissions: 'not json' } }]
    rows.groups = []
    expect(await userTokenGrants('fixture-user')).toEqual({ roles: ['BROKEN'], permissions: [] })
  })
})
