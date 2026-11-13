import { Hono, type MiddlewareHandler } from 'hono'
import { beforeEach, expect, it, vi } from 'vitest'
import { errorHandler } from '../middleware/error-handler.js'

const state = vi.hoisted(() => ({
  roles: [] as string[],
  permissions: ['iam:clients:write'] as string[],
  create: vi.fn(async (input: { data: Record<string, unknown> }) => ({
    id: 'generated-id',
    name: input.data.name,
  })),
}))
vi.mock('../db/client.js', () => ({
  prisma: { client: { findUnique: vi.fn(async () => null), create: state.create } },
}))
vi.mock('../config/env.js', () => ({ env: { RELAX_AUTH_LIMITS: false, RATE_LIMIT_WINDOW_MS: 900_000 } }))
vi.mock('../middleware/auth.js', () => ({
  authMiddleware: (async (c, next) => {
    c.set('principal', {
      sub: 'fixture-admin',
      actorType: 'USER',
      username: 'admin',
      email: 'admin@example.com',
      roles: state.roles,
      permissions: state.permissions,
      sessionId: undefined,
      clientId: undefined,
    })
    await next()
  }) satisfies MiddlewareHandler,
}))
vi.mock('../services/audit-service.js', () => ({ logAuditEvent: vi.fn() }))
vi.mock('../services/token-service.js', () => ({
  clientCredentialsPermissionCeiling: (name: string) =>
    name === 'example-worker' ? ['example:write'] : [],
}))
vi.mock('argon2', () => ({ default: { hash: async () => 'fixture-hash', argon2id: 2 } }))

const { clientsRouter } = await import('./clients.js')
const app = new Hono().route('/clients', clientsRouter).onError(errorHandler)
const create = (body: Record<string, unknown>) =>
  app.request('/clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
const signIn = {
  name: 'example-portal-two',
  clientType: 'public',
  firstParty: true,
  grantTypes: ['authorization_code'],
  redirectUris: ['https://portal.example.com/callback'],
}
const machine = {
  name: 'example-batch',
  secret: 'fixture-secret-of-enough-length',
  grantTypes: ['client_credentials'],
}

beforeEach(() => {
  state.create.mockClear()
  state.roles = []
  state.permissions = ['iam:clients:write']
})

it('only SUPER_ADMIN may create a sign-in client, as for changing one', async () => {
  const refused = await create(signIn)
  expect(refused.status).toBe(403)
  expect(await refused.json()).toMatchObject({ error: 'PRIVILEGE_ESCALATION' })
  // The schema default is a sign-in client too.
  expect((await create({ name: 'example-default', secret: machine.secret })).status).toBe(403)
  expect(state.create).not.toHaveBeenCalled()

  state.roles = ['SUPER_ADMIN']
  expect((await create(signIn)).status).toBe(201)
  expect(state.create).toHaveBeenCalledOnce()
})

it('a client administrator still creates machine clients within their own permissions', async () => {
  expect((await create(machine)).status).toBe(201)
  const refused = await create({ ...machine, name: 'example-worker' })
  expect(refused.status).toBe(403)
  state.permissions = ['iam:clients:write', 'example:write']
  expect((await create({ ...machine, name: 'example-worker' })).status).toBe(201)
})
