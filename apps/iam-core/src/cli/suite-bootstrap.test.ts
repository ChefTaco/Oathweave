import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  chmodSync,
  symlinkSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it } from 'vitest'
import {
  suiteBootstrapSchema,
  loadSuiteBootstrap,
  suiteAdminPermissions,
} from '../../prisma/suite-bootstrap.js'
const fixture = () => ({
  schema: 1,
  adminId: 'synthetic-initial-identity',
  clients: [
    {
      id: 'hivexui-oathweave',
      audience: 'oathweave',
      permissions: ['iam:users:read'],
      redirectUris: ['https://console.example.com/auth/callback'],
      firstParty: true,
    },
    {
      id: 'hivexui-emberpath',
      audience: 'emberpath',
      permissions: ['router:providers:read'],
      redirectUris: ['https://console.example.com/auth/callback'],
      firstParty: true,
    },
  ],
})
const roots: string[] = []
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true })
})
it('derives explicit resource grants with no wildcard administrator credential', () => {
  expect(suiteAdminPermissions(suiteBootstrapSchema.parse(fixture()))).toEqual([
    'iam:users:read',
    'router:providers:read',
  ])
})
it('accepts the Ardent Project Studio browser client only with its own resource grants', () => {
  const value = fixture()
  value.clients.push({
    id: 'hivexui-ardentstudio',
    audience: 'ardentstudio',
    permissions: ['ardentstudio:projects:read', 'ardentstudio:agents:admin'],
    redirectUris: ['https://console.example.com/auth/callback'],
    firstParty: true,
  })
  expect(suiteAdminPermissions(suiteBootstrapSchema.parse(value))).toContain(
    'ardentstudio:agents:admin',
  )
  value.clients[2]!.permissions = ['magnus:ardent']
  expect(() => suiteBootstrapSchema.parse(value)).toThrow()
})
it('rejects mixed audiences, duplicate clients and unsafe redirects before seeding', () => {
  const mutations = [
    (value: ReturnType<typeof fixture>) => {
      value.clients[0]!.permissions = ['router:providers:write']
    },
    (value: ReturnType<typeof fixture>) => {
      value.clients[0]!.permissions = ['*']
    },
    (value: ReturnType<typeof fixture>) => {
      value.clients[1]!.id = value.clients[0]!.id
    },
    (value: ReturnType<typeof fixture>) => {
      value.clients[1]!.redirectUris = [
        'https://other.example.com/auth/callback',
      ]
    },
    (value: ReturnType<typeof fixture>) => {
      value.clients[1]!.redirectUris = [
        'https://console.example.com/auth/callback?token=obviously-fake',
      ]
    },
    (value: ReturnType<typeof fixture>) => {
      value.clients[1]!.redirectUris = [
        'https://user:obviously-fake@console.example.com/auth/callback',
      ]
    },
  ]
  for (const mutate of mutations) {
    const value = fixture()
    mutate(value)
    expect(() => suiteBootstrapSchema.parse(value)).toThrow()
  }
})
it('requires protected product-owned configuration matching the runtime permission ceilings', () => {
  const root = mkdtempSync(join(tmpdir(), 'oathweave-suite-seed-'))
  roots.push(root)
  const path = join(root, 'bootstrap.json'),
    value = fixture()
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
  const policies = Object.fromEntries(
    value.clients.map((client) => [
      client.id,
      { audience: client.audience, permissions: client.permissions },
    ]),
  )
  const source = {
    OATHWEAVE_SUITE_BOOTSTRAP_FILE: path,
    IAM_BROWSER_CLIENT_POLICIES: JSON.stringify(policies),
  }
  expect(loadSuiteBootstrap(source)?.adminId).toBe(value.adminId)
  expect(() =>
    loadSuiteBootstrap({ ...source, IAM_BROWSER_CLIENT_POLICIES: '{}' }),
  ).toThrow(/permission ceilings/)
  chmodSync(path, 0o644)
  expect(() => loadSuiteBootstrap(source)).toThrow(/mode-0600/)
  chmodSync(path, 0o600)
  symlinkSync(path, join(root, 'linked.json'))
  expect(() =>
    loadSuiteBootstrap({
      ...source,
      OATHWEAVE_SUITE_BOOTSTRAP_FILE: join(root, 'linked.json'),
    }),
  ).toThrow(/mode-0600/)
})
it('admits an explicit Embermend browser audience with its own finite permission ceiling', () => {
  const value = fixture()
  value.clients.push({
    id: 'hivexui-embermend', audience: 'embermend',
    permissions: ['embermend:read', 'embermend:assess', 'embermend:prepare', 'embermend:approve'],
    redirectUris: ['https://console.example.com/auth/callback'], firstParty: true,
  })
  const parsed = suiteBootstrapSchema.parse(value)
  expect(suiteAdminPermissions(parsed)).toEqual(expect.arrayContaining(['embermend:read', 'embermend:approve']))
  const product = value.clients.find(client => client.id === 'hivexui-embermend')
  if (!product) throw new Error('Missing fixture client')
  for (const permissions of [['magnus:admin'], ['iam:users:write'], ['embermend:*']]) {
    product.permissions = permissions
    expect(() => suiteBootstrapSchema.parse(value)).toThrow()
  }
})
