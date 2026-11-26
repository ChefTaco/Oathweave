/**
 * A Hive suite install as the controller configures it: a non-URL native `JWT_ISSUER`, an HTTPS
 * browser issuer, and no `IAM_PUBLIC_URL`. Native discovery has no URLs to publish and says so, but
 * nothing the suite relies on depends on it: the JWKS route, sign-in, UserInfo and service tokens
 * keep working.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const NATIVE_ISSUER = 'oathweave-fixture-installation'
const { startRealApp } = await import('../test-support/real-app.js')
delete process.env['IAM_PUBLIC_URL']
const harness = await startRealApp({
  JWT_ISSUER: NATIVE_ISSUER,
  IAM_BROWSER_ISSUER: 'https://console.example.com/api/oathweave',
  IAM_BROWSER_CLIENT_POLICIES: JSON.stringify({ 'hivexui-oathweave': { audience: 'oathweave', permissions: ['iam:users:read'] } }),
})
const { validateEnv } = await import('../config/env-schema.js')
const SECRET = 'suite-service-fixture-secret-'.padEnd(43, 's')

beforeAll(async () => {
  await harness.createClient({ id: 'suite-service', secret: SECRET, grantTypes: ['client_credentials'] })
  await harness.createUser({ username: 'lena', password: 'lena-fixture-password' })
})

describe('a suite install without IAM_PUBLIC_URL', () => {
  it('serves the JWKS that verifies native tokens', async () => {
    const jwks = await harness.request('/api/v1/oauth/jwks')
    expect(jwks.status).toBe(200)
    const keys = createLocalJWKSet((await jwks.json()) as JSONWebKeySet)

    const issued = await harness.request('/api/v1/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'suite-service', client_secret: SECRET }).toString(),
    })
    expect(issued.status).toBe(200)
    const { access_token } = (await issued.json()) as { access_token: string }
    await expect(jwtVerify(access_token, keys, { issuer: NATIVE_ISSUER })).resolves.toBeTruthy()

    const person = await harness.login('lena', 'lena-fixture-password')
    await expect(jwtVerify(person.accessToken, keys, { issuer: NATIVE_ISSUER })).resolves.toBeTruthy()
    expect((await harness.request('/api/v1/oauth/userinfo', { headers: { authorization: `Bearer ${person.accessToken}` } })).status).toBe(200)
  })

  it('answers native discovery with 503 and no cache, naming the setting', async () => {
    for (const path of ['/api/v1/oauth/.well-known/openid-configuration', '/.well-known/openid-configuration']) {
      const response = await harness.request(path)
      expect(response.status, path).toBe(503)
      expect(response.headers.get('cache-control')).toBe('no-store')
      expect(await response.json()).toMatchObject({ error: 'DISCOVERY_UNCONFIGURED' })
    }
  })

  it('accepts the suite-internal endpoint as IAM_PUBLIC_URL', () => {
    const base = { DATABASE_URL: 'file:/tmp/x.db', JWT_PRIVATE_KEY_PATH: '/tmp/a', JWT_PUBLIC_KEY_PATH: '/tmp/b', COOKIE_SECRET: 'x'.repeat(32), IAM_AGENT_SECRET: 'x'.repeat(16), JWT_ISSUER: NATIVE_ISSUER }
    expect(validateEnv({ ...base, IAM_PUBLIC_URL: 'https://oathweave:4200' }).ok).toBe(true)
    expect(validateEnv({ ...base, IAM_PUBLIC_URL: 'http://oathweave:4200' }).ok).toBe(false)
  })
})
