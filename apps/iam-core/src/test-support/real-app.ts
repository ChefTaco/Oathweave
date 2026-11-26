/**
 * The real server (routes, services, Prisma) on a disposable SQLite database built from the
 * bundled migrations. Redis and the audit queue are in-memory fakes, which the test file installs:
 *
 *   vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
 *   vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)
 *   const harness = await startRealApp({ ... })
 *
 * Import it only through `startRealApp`, after the mocks, because the server reads its
 * configuration when its modules load.
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export interface RealApp {
  request: (path: string, init?: RequestInit) => Promise<Response>
  directory: string
  prisma: typeof import('../db/client.js')['prisma']
  hashSecret: (secret: string) => Promise<string>
  createUser: (input: { username: string; password: string; roles?: { name: string; permissions: string[] }[]; email?: string }) => Promise<{ id: string }>
  createClient: (input: { id: string; secret?: string; clientType?: 'public' | 'confidential'; grantTypes: string[]; redirectUris?: string[]; firstParty?: boolean; allowedIps?: string[] }) => Promise<void>
  login: (username: string, password: string) => Promise<{ accessToken: string; refreshToken: string; sessionId: string }>
}

export async function startRealApp(extraEnv: Record<string, string> = {}): Promise<RealApp> {
  const directory = mkdtempSync(join(tmpdir(), 'oathweave-real-app-'))
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  writeFileSync(join(directory, 'private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
  writeFileSync(join(directory, 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }))
  const database = join(directory, 'iam.db')
  Object.assign(process.env, {
    NODE_ENV: 'test',
    DATABASE_URL: `file:${database}`,
    JWT_PRIVATE_KEY_PATH: join(directory, 'private.pem'),
    JWT_PUBLIC_KEY_PATH: join(directory, 'public.pem'),
    JWT_ISSUER: 'https://identity.example.com',
    COOKIE_SECRET: randomBytes(32).toString('hex'),
    IAM_AGENT_SECRET: randomBytes(16).toString('hex'),
    CORS_ORIGIN: 'https://console.example.com',
    TRUSTED_PROXY_IPS: '',
    RATE_LIMIT_MAX_ATTEMPTS: '1000',
    ...extraEnv,
  })
  const { applyMigrations } = await import('../cli/migrate.js')
  const { MIGRATIONS_DIR } = await import('../cli/paths.js')
  applyMigrations(database, MIGRATIONS_DIR)
  const { createApp } = await import('../server.js')
  const { prisma } = await import('../db/client.js')
  const argon2 = (await import('argon2')).default
  const app = createApp()
  const hashSecret = (secret: string) => argon2.hash(secret, { type: argon2.argon2id, memoryCost: 1024, timeCost: 1, parallelism: 1 })

  const request = (path: string, init: RequestInit = {}) =>
    Promise.resolve(app.request(path, init, { incoming: { socket: { remoteAddress: '198.51.100.20' } } }))

  return {
    request,
    directory,
    prisma,
    hashSecret,
    async createUser({ username, password, roles = [], email }) {
      const user = await prisma.user.create({
        data: {
          username,
          email: email ?? `${username}@example.com`,
          displayName: username,
          passwordHash: await hashSecret(password),
          passwordChangedAt: new Date(),
        },
      })
      for (const role of roles) {
        const stored = await prisma.role.upsert({
          where: { name: role.name },
          create: { name: role.name, label: role.name, permissions: JSON.stringify(role.permissions) },
          update: {},
        })
        await prisma.userRoleAssignment.create({ data: { userId: user.id, roleId: stored.id } })
      }
      return { id: user.id }
    },
    async createClient({ id, secret, clientType = 'confidential', grantTypes, redirectUris = [], firstParty = false, allowedIps = [] }) {
      await prisma.client.create({
        data: {
          id,
          name: id,
          clientType,
          secretHash: secret ? await hashSecret(secret) : null,
          grantTypes: JSON.stringify(grantTypes),
          redirectUris: JSON.stringify(redirectUris),
          firstParty,
          allowedIps: JSON.stringify(allowedIps),
        },
      })
    },
    async login(username, password) {
      const response = await request('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (response.status !== 200) throw new Error(`login failed: ${response.status} ${await response.text()}`)
      return (await response.json()) as { accessToken: string; refreshToken: string; sessionId: string }
    },
  }
}
