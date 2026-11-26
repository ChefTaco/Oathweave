/** Token exchange (RFC 8693) delegation against the real server. */
import { decodeJwt } from 'jose'
import { beforeAll, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'
const ISSUER = 'https://identity.example.com'
const { startRealApp } = await import('../test-support/real-app.js')
const harness = await startRealApp({
  JWT_ISSUER: ISSUER,
  IAM_PUBLIC_URL: ISSUER,
  IAM_MACHINE_CLIENT_POLICIES: JSON.stringify({ 'gateway': { audience: 'gateway', permissions: ['gateway:read'], rotationOwner: 'fixture' } }),
  IAM_TOKEN_EXCHANGE_POLICIES: JSON.stringify({
    gateway: { subjectAudiences: ['gateway'], audiences: { memory: { permissions: ['memory:read', 'memory:write'], lifetimeSeconds: 120 } } },
  }),
})

const SECRET = 'gateway-exchange-secret-'.padEnd(43, 'g')
const form = (values: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(values).toString(),
})
const exchange = (subjectToken: string, extra: Record<string, string> = {}, clientId = 'gateway', secret = SECRET) =>
  harness.request('/api/v1/oauth/token', form({
    grant_type: EXCHANGE, client_id: clientId, client_secret: secret,
    subject_token: subjectToken, subject_token_type: ACCESS, audience: 'memory', ...extra,
  }))
const REDIRECT = 'https://gateway.example.com/callback'
let person: { accessToken: string; sessionId: string }
let personId: string

/** A token the gateway received for the person: its own sign-in (authorization code) flow. */
async function issuedToGateway(nativeToken: string): Promise<string> {
  const authorized = await harness.request('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { authorization: `Bearer ${nativeToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ clientId: 'gateway', redirectUri: REDIRECT, responseType: 'code', scope: 'openid', consent: 'approve' }),
  })
  const { code } = (await authorized.json()) as { code: string }
  const exchanged = await harness.request('/api/v1/oauth/token', form({ grant_type: 'authorization_code', client_id: 'gateway', client_secret: SECRET, code, redirect_uri: REDIRECT }))
  return ((await exchanged.json()) as { access_token: string }).access_token
}

beforeAll(async () => {
  await harness.createClient({ id: 'gateway', secret: SECRET, grantTypes: ['client_credentials', 'authorization_code', EXCHANGE], redirectUris: [REDIRECT] })
  await harness.createClient({ id: 'other', secret: SECRET, grantTypes: [EXCHANGE] })
  personId = (await harness.createUser({ username: 'kim', password: 'kim-fixture-password', roles: [{ name: 'reader', permissions: ['memory:read'] }] })).id
  person = await harness.login('kim', 'kim-fixture-password')
})

describe('token exchange', () => {
  it('is advertised in discovery', async () => {
    expect((await (await harness.request('/.well-known/openid-configuration')).json()).grant_types_supported).toContain(EXCHANGE)
  })

  it('mints a narrow, audience-bound token for the person, acted on by the client', async () => {
    const subject = await issuedToGateway(person.accessToken)
    const response = await exchange(subject)
    expect(response.status).toBe(200)
    const body = (await response.json()) as { access_token: string; issued_token_type: string; token_type: string; expires_in: number; scope: string; refresh_token?: string }
    expect(body).toMatchObject({ issued_token_type: ACCESS, token_type: 'Bearer', scope: 'memory:read' })
    expect(body.refresh_token).toBeUndefined()
    expect(body.expires_in).toBeLessThanOrEqual(120)
    // memory:write is in the policy but the person does not hold it.
    const claims = decodeJwt(body.access_token)
    expect(claims).toMatchObject({ sub: personId, aud: 'memory', iss: ISSUER, act: { sub: 'gateway' }, permissions: ['memory:read'], roles: [] })

    // It is no key to this API, and it dies with the person's session.
    expect((await harness.request('/api/v1/auth/me', { headers: { authorization: `Bearer ${body.access_token}` } })).status).toBe(401)
    const introspected = await harness.request('/api/v1/oauth/introspect', form({ client_id: 'gateway', client_secret: SECRET, token: body.access_token }))
    expect(await introspected.json()).toMatchObject({ active: true, aud: 'memory' })
    expect(claims['sessionId']).toBe(decodeJwt(subject)['sessionId'])
    await harness.request(`/api/v1/auth/sessions/${String(claims['sessionId'])}`, { method: 'DELETE', headers: { authorization: `Bearer ${person.accessToken}` } })
    expect(await (await harness.request('/api/v1/oauth/introspect', form({ client_id: 'gateway', client_secret: SECRET, token: body.access_token }))).json()).toEqual({ active: false })
    person = await harness.login('kim', 'kim-fixture-password')
  })

  it('refuses what the policy does not allow', async () => {
    const subject = await issuedToGateway(person.accessToken)
    expect(await (await exchange(subject, { audience: 'billing' })).json()).toMatchObject({ error: 'invalid_target' })
    expect(await (await exchange(subject, { scope: 'memory:write' })).json()).toMatchObject({ error: 'invalid_scope' })
    expect(await (await exchange(subject, { subject_token_type: 'urn:ietf:params:oauth:token-type:id_token' })).json()).toMatchObject({ error: 'invalid_request' })
    expect(await (await exchange(subject, {}, 'other')).json()).toMatchObject({ error: 'unauthorized_client' })
    expect((await exchange(subject, {}, 'gateway', 'wrong-secret-'.padEnd(43, 'w'))).status).toBe(401)
    expect(await (await exchange('not-a-token')).json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('refuses a token that was not addressed to the client, and chains', async () => {
    // The person's own sign-in token was issued to no client.
    expect(await (await exchange(person.accessToken)).json()).toMatchObject({ error: 'invalid_grant' })
    const machine = await harness.request('/api/v1/oauth/token', form({ grant_type: 'client_credentials', client_id: 'gateway', client_secret: SECRET, scope: 'gateway:read' }))
    const machineToken = ((await machine.json()) as { access_token: string }).access_token
    // A client_credentials token is no person's token.
    expect(await (await exchange(machineToken)).json()).toMatchObject({ error: 'invalid_grant' })
    const delegated = ((await (await exchange(await issuedToGateway(person.accessToken))).json()) as { access_token: string }).access_token
    expect(await (await exchange(delegated)).json()).toMatchObject({ error: 'invalid_grant' })
  })
})
