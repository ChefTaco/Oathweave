import { Hono, type MiddlewareHandler } from 'hono'
import { errorHandler } from '../middleware/error-handler.js'
import { beforeEach, expect, it, vi } from 'vitest'
const database = vi.hoisted(() => ({
  client: {
    findUnique: vi.fn(async () => null),
    create: vi.fn(async (input: { data: Record<string, unknown> }) => ({
      id: input.data.id ?? 'native-generated-id',
      name: input.data.name,
      clientType: input.data.clientType,
    })),
  },
}))
vi.mock('../db/client.js', () => ({ prisma: database }))
vi.mock('../middleware/auth.js', () => ({
  authMiddleware: (async (c, next) => {
    c.set('principal', {
      sub: 'fixture-admin',
      actorType: 'USER',
      username: 'admin',
      email: 'admin@example.com',
      roles: [],
      permissions: ['iam:clients:write'],
      sessionId: undefined,
      clientId: undefined,
    })
    await next()
  }) satisfies MiddlewareHandler,
}))
vi.mock('../services/audit-service.js', () => ({ logAuditEvent: vi.fn() }))
vi.mock('../services/privilege-guard.js', () => ({
  resolveActor: vi.fn(),
  assertMayGrantPermissions: vi.fn(),
  assertMayManageClient: vi.fn(),
}))
vi.mock('../services/token-service.js', () => ({
  clientCredentialsPermissionCeiling: () => [],
}))
vi.stubEnv(
  'IAM_BROWSER_CLIENT_POLICIES',
  JSON.stringify({
    'hivexui-emberpath': {
      audience: 'emberpath',
      permissions: ['router:providers:read'],
    },
  }),
)
const { clientsRouter } = await import('./clients.js')
const app = new Hono().route('/clients', clientsRouter)
app.onError(errorHandler)
beforeEach(() => {
  database.client.create.mockClear()
  database.client.findUnique.mockClear()
})
it('the authorized API creates a public client with the policy identifier used by OAuth', async () => {
  const response = await app.request('/clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'hivexui-emberpath',
      clientType: 'public',
      firstParty: true,
      grantTypes: ['authorization_code'],
      redirectUris: ['https://console.example.com/auth/callback'],
    }),
  })
  expect(response.status).toBe(201)
  expect((await response.json()).client.id).toBe('hivexui-emberpath')
  expect(database.client.create.mock.calls[0]?.[0].data).toMatchObject({
    id: 'hivexui-emberpath',
    secretHash: null,
    clientType: 'public',
  })
})
it('unconfigured native public clients retain generated identifiers', async () => {
  const response = await app.request('/clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'example-client',
      clientType: 'public',
      grantTypes: ['authorization_code'],
    }),
  })
  expect(response.status).toBe(201)
  expect((await response.json()).client.id).toBe('native-generated-id')
  expect(database.client.create.mock.calls[0]?.[0].data).not.toHaveProperty(
    'id',
  )
})

it('a conflicting stable identifier is held without replacing the existing client', async () => {
  database.client.findUnique
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({ id: 'hivexui-emberpath' } as never)
  const response = await app.request('/clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'hivexui-emberpath',
      clientType: 'public',
      grantTypes: ['authorization_code'],
    }),
  })
  expect(response.status).toBe(409)
  expect(database.client.create).not.toHaveBeenCalled()
})
