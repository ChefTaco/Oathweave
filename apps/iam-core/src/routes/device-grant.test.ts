/** The device authorization grant (RFC 8628) against the real server. */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const ISSUER = 'https://identity.example.com'
const VERIFY = 'https://console.example.com/device'
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
const { startRealApp } = await import('../test-support/real-app.js')
const { resetFakeRedis, auditEvents } = await import('../test-support/fake-redis.js')
const harness = await startRealApp({ JWT_ISSUER: ISSUER, IAM_PUBLIC_URL: ISSUER, IAM_DEVICE_VERIFICATION_URL: VERIFY })

const form = (values: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(values).toString(),
})
const SECRET = 'device-confidential-secret-'.padEnd(43, 'd')
let person: { accessToken: string }
let personId: string

beforeAll(async () => {
  await harness.createClient({ id: 'cli', clientType: 'public', grantTypes: [DEVICE_GRANT, 'refresh_token'] })
  await harness.createClient({ id: 'agent', secret: SECRET, grantTypes: [DEVICE_GRANT] })
  await harness.createClient({ id: 'no-device', clientType: 'public', grantTypes: ['authorization_code'], redirectUris: ['https://app.example.com/cb'] })
  personId = (await harness.createUser({ username: 'judy', password: 'judy-fixture-password', roles: [{ name: 'operator', permissions: ['magnus:nodes:read'] }] })).id
  person = await harness.login('judy', 'judy-fixture-password')
})
beforeEach(() => resetFakeRedis())

async function start(clientId: string, extra: Record<string, string> = {}) {
  const response = await harness.request('/api/v1/oauth/device_authorization', form({ client_id: clientId, scope: 'openid profile', ...extra }))
  expect(response.status).toBe(200)
  return (await response.json()) as { device_code: string; user_code: string; verification_uri: string; verification_uri_complete: string; interval: number; expires_in: number }
}
const poll = (clientId: string, deviceCode: string, extra: Record<string, string> = {}) =>
  harness.request('/api/v1/oauth/token', form({ grant_type: DEVICE_GRANT, client_id: clientId, device_code: deviceCode, ...extra }))
const decide = (userCode: string, decision: 'approve' | 'deny', token = person.accessToken) =>
  harness.request('/api/v1/oauth/device', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ userCode, decision }),
  })
/** Let the next poll come after the interval without waiting for it. */
const sincePoll = (deviceCode: string) =>
  harness.prisma.deviceAuthorization.updateMany({ where: { status: 'pending' }, data: { lastPolledAt: new Date(Date.now() - 60_000) } }).then(() => deviceCode)

describe('the device authorization grant', () => {
  it('is advertised in discovery', async () => {
    const metadata = await (await harness.request('/.well-known/openid-configuration')).json()
    expect(metadata.device_authorization_endpoint).toBe(`${ISSUER}/api/v1/oauth/device_authorization`)
    expect(metadata.grant_types_supported).toContain(DEVICE_GRANT)
  })

  it('signs a person in on a device that never sees their password', async () => {
    const started = await start('cli')
    expect(started.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/)
    expect(started).toMatchObject({ verification_uri: VERIFY, interval: 5, expires_in: 600 })
    expect(started.verification_uri_complete).toBe(`${VERIFY}?user_code=${started.user_code}`)

    const pending = await poll('cli', started.device_code)
    expect(pending.status).toBe(400)
    expect(await pending.json()).toMatchObject({ error: 'authorization_pending' })
    const fast = await poll('cli', started.device_code)
    expect(await fast.json()).toMatchObject({ error: 'slow_down' })

    // The person reads the request (code typed in lower case, without the dash) and approves it.
    const shown = await harness.request(`/api/v1/oauth/device?user_code=${started.user_code.replace('-', '').toLowerCase()}`, { headers: { authorization: `Bearer ${person.accessToken}` } })
    expect(await shown.json()).toMatchObject({ clientId: 'cli', scope: 'openid profile' })
    expect((await decide(started.user_code, 'approve')).status).toBe(200)

    const granted = await poll('cli', await sincePoll(started.device_code))
    expect(granted.status).toBe(200)
    const tokens = (await granted.json()) as { access_token: string; refresh_token?: string; id_token?: string; scope: string }
    expect(tokens.scope).toBe('openid profile')
    expect(tokens.refresh_token).toBeTypeOf('string')
    expect(tokens.id_token).toBeTypeOf('string')
    const me = await harness.request('/api/v1/oauth/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } })
    expect(await me.json()).toMatchObject({ sub: personId, preferred_username: 'judy' })
    expect(auditEvents.map((event) => event.eventType)).toEqual(expect.arrayContaining(['oauth.device_authorization', 'oauth.device_approved', 'oauth.device_token']))

    // One exchange per device code.
    expect(await (await poll('cli', started.device_code)).json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('reports a denial, refuses another client and expired codes', async () => {
    const denied = await start('cli')
    expect((await decide(denied.user_code, 'deny')).status).toBe(200)
    expect(await (await poll('cli', await sincePoll(denied.device_code))).json()).toMatchObject({ error: 'access_denied' })
    // Once decided, the code cannot be approved after all.
    expect((await decide(denied.user_code, 'approve')).status).toBe(404)

    const other = await start('cli')
    expect(await (await poll('agent', other.device_code, { client_secret: SECRET })).json()).toMatchObject({ error: 'invalid_grant' })

    await harness.prisma.deviceAuthorization.updateMany({ where: { status: 'pending' }, data: { expiresAt: new Date(Date.now() - 1000) } })
    expect(await (await poll('cli', other.device_code)).json()).toMatchObject({ error: 'expired_token' })
    expect((await decide(other.user_code, 'approve')).status).toBe(404)
  })

  it('needs a confidential client to authenticate, and the grant on the client', async () => {
    expect((await harness.request('/api/v1/oauth/device_authorization', form({ client_id: 'agent' }))).status).toBe(401)
    const started = await start('agent', { client_secret: SECRET })
    expect((await decide(started.user_code, 'approve')).status).toBe(200)
    expect((await poll('agent', await sincePoll(started.device_code))).status).toBe(401)
    const granted = await poll('agent', started.device_code, { client_secret: SECRET })
    expect(granted.status).toBe(200)
    // No refresh_token grant on this client: no refresh token.
    expect((await granted.json()).refresh_token).toBeUndefined()

    const refused = await harness.request('/api/v1/oauth/device_authorization', form({ client_id: 'no-device' }))
    expect(refused.status).toBe(400)
    expect(await refused.json()).toMatchObject({ error: 'unauthorized_client' })
  })

  it('issues a token for the device client that cannot approve another device or manage Oathweave', async () => {
    const first = await start('cli')
    expect((await decide(first.user_code, 'approve')).status).toBe(200)
    const tokens = (await (await poll('cli', await sincePoll(first.device_code))).json()) as { access_token: string }
    const claims = JSON.parse(Buffer.from(tokens.access_token.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>
    expect(claims).toMatchObject({ aud: 'cli', clientId: 'cli' })

    const second = await start('cli')
    const approved = await decide(second.user_code, 'approve', tokens.access_token)
    expect(approved.status).toBe(401)
    expect(await approved.json()).toMatchObject({ error: 'INVALID_AUDIENCE' })
    expect((await harness.request('/api/v1/roles', { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(401)
    expect((await harness.request('/api/v1/oauth/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(200)
  })

  it('needs a signed-in person to approve', async () => {
    const started = await start('cli')
    const anonymous = await harness.request('/api/v1/oauth/device', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://console.example.com' },
      body: JSON.stringify({ userCode: started.user_code, decision: 'approve' }),
    })
    expect(anonymous.status).toBe(401)
    expect((await decide('BBBB-BBBB', 'approve')).status).toBe(404)
  })
})
