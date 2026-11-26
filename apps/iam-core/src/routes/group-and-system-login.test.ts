/**
 * Group management and the PAM login check against the real server: deleting or changing a group
 * needs standing over the roles it grants, and a role granted through a group admits system login
 * exactly as a direct assignment does.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const { startRealApp } = await import('../test-support/real-app.js')
const AGENT_SECRET = 'agent-fixture-secret-group-pam'
const harness = await startRealApp({ IAM_AGENT_SECRET: AGENT_SECRET })

let groupAdmin: { accessToken: string }
let superAdmin: { accessToken: string }
let adminsGroup: string
let plainGroup: string

const as = (token: string, init: RequestInit = {}) => ({
  ...init,
  headers: { 'content-type': 'application/json', ...(init.headers as Record<string, string>), authorization: `Bearer ${token}` },
})

beforeAll(async () => {
  await harness.createUser({ username: 'root', password: 'root-fixture-password', roles: [{ name: 'SUPER_ADMIN', permissions: ['iam:groups:read', 'iam:groups:write'] }] })
  await harness.createUser({ username: 'gwen', password: 'gwen-fixture-password', roles: [{ name: 'GROUP_ADMIN', permissions: ['iam:groups:read', 'iam:groups:write'] }] })
  superAdmin = await harness.login('root', 'root-fixture-password')
  groupAdmin = await harness.login('gwen', 'gwen-fixture-password')
  const superRole = await harness.prisma.role.findUniqueOrThrow({ where: { name: 'SUPER_ADMIN' } })
  adminsGroup = (await harness.prisma.group.create({ data: { name: 'admins', roles: { create: [{ roleId: superRole.id }] } } })).id
  plainGroup = (await harness.prisma.group.create({ data: { name: 'plain' } })).id
})

describe('group management', () => {
  it('stops a group writer from deleting or renaming a group that grants more than they hold', async () => {
    const deleted = await harness.request(`/api/v1/groups/${adminsGroup}`, as(groupAdmin.accessToken, { method: 'DELETE' }))
    expect(deleted.status).toBe(403)
    const renamed = await harness.request(`/api/v1/groups/${adminsGroup}`, as(groupAdmin.accessToken, { method: 'PATCH', body: JSON.stringify({ name: 'renamed' }) }))
    expect(renamed.status).toBe(403)
    expect(await harness.prisma.group.findUnique({ where: { id: adminsGroup } })).toMatchObject({ name: 'admins' })
  })

  it('lets a group writer delete a group they could manage, and SUPER_ADMIN any group', async () => {
    expect((await harness.request(`/api/v1/groups/${plainGroup}`, as(groupAdmin.accessToken, { method: 'DELETE' }))).status).toBe(200)
    expect((await harness.request(`/api/v1/groups/${adminsGroup}`, as(superAdmin.accessToken, { method: 'DELETE' }))).status).toBe(200)
    expect(await harness.prisma.group.count({ where: { id: { in: [plainGroup, adminsGroup] } } })).toBe(0)
  })
})

describe('POST /system-users/check', () => {
  const check = (linuxUsername: string) =>
    harness.request('/api/v1/system-users/check', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-token': AGENT_SECRET },
      body: JSON.stringify({ linuxUsername, clientIp: '192.0.2.5', hostName: 'host-a', agentToken: AGENT_SECRET }),
    })

  it('admits a person whose iam:system:login comes from a group', async () => {
    const { id } = await harness.createUser({ username: 'ivan', password: 'ivan-fixture-password' })
    await harness.prisma.systemUser.create({ data: { userId: id, linuxUsername: 'ivan' } })
    expect(await (await check('ivan')).json()).toMatchObject({ allowed: false, reason: 'insufficient_permissions' })

    const role = await harness.prisma.role.create({ data: { name: 'SHELL', label: 'Shell', permissions: JSON.stringify(['iam:system:login']) } })
    await harness.prisma.group.create({ data: { name: 'shell-users', roles: { create: [{ roleId: role.id }] }, members: { create: [{ userId: id }] } } })
    expect(await (await check('ivan')).json()).toMatchObject({ allowed: true, userId: id })
  })
})
