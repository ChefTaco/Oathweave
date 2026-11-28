/** Token exchange (RFC 8693) delegation against the real server. */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { decodeJwt, decodeProtectedHeader, importPKCS8, SignJWT } from 'jose'
import { beforeAll, describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'
const ISSUER = 'https://identity.example.com'
const REFRESH = 'urn:ietf:params:oauth:token-type:refresh_token'
const { startRealApp } = await import('../test-support/real-app.js')
const { auditEvents } = await import('../test-support/fake-redis.js')
const machine = (audience: string) => ({ audience, permissions: [`${audience}:read`], rotationOwner: 'fixture' })
const harness = await startRealApp({
  JWT_ISSUER: ISSUER,
  IAM_PUBLIC_URL: ISSUER,
  IAM_MACHINE_CLIENT_POLICIES: JSON.stringify({
    gateway: machine('gateway'), relay: machine('relay'),
    // Agents whose client_credentials tokens are addressed to the gateway, or elsewhere.
    agent: { ...machine('gateway'), permissions: ['gateway:read'] }, stranger: { ...machine('gateway'), permissions: ['gateway:read'] },
    retired: { ...machine('gateway'), permissions: ['gateway:read'] }, roaming: machine('elsewhere'),
  }),
  IAM_TOKEN_EXCHANGE_POLICIES: JSON.stringify({
    gateway: {
      subjectAudiences: ['gateway'],
      audiences: {
        memory: { permissions: ['memory:read', 'memory:write'], lifetimeSeconds: 120, actors: ['agent', 'retired', 'roaming'] },
        archive: { permissions: ['memory:read'], lifetimeSeconds: 60 },
      },
    },
    // Opts in to refresh-token subjects.
    relay: { subjectTokenTypes: ['access_token', 'refresh_token'], audiences: { memory: { permissions: ['memory:read'], lifetimeSeconds: 90 } } },
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
const RELAY_REDIRECT = 'https://relay.example.com/callback'
const clientCredentials = async (clientId: string) => {
  const response = await harness.request('/api/v1/oauth/token', form({ grant_type: 'client_credentials', client_id: clientId, client_secret: SECRET, scope: `${clientId === 'roaming' ? 'elsewhere' : clientId === 'relay' ? 'relay' : 'gateway'}:read` }))
  return ((await response.json()) as { access_token: string }).access_token
}
const errorOf = async (response: Response) => (await response.json()) as { error: string; error_description: string }
let person: { accessToken: string; sessionId: string }
let personId: string

/** A token the gateway received for the person: its own sign-in (authorization code) flow. */
async function signIn(nativeToken: string, clientId = 'gateway', redirectUri = REDIRECT): Promise<{ access_token: string; refresh_token?: string }> {
  const authorized = await harness.request('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { authorization: `Bearer ${nativeToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ clientId, redirectUri, responseType: 'code', scope: 'openid', consent: 'approve' }),
  })
  const { code } = (await authorized.json()) as { code: string }
  const exchanged = await harness.request('/api/v1/oauth/token', form({ grant_type: 'authorization_code', client_id: clientId, client_secret: SECRET, code, redirect_uri: redirectUri }))
  return (await exchanged.json()) as { access_token: string; refresh_token?: string }
}
async function issuedToGateway(nativeToken: string): Promise<string> {
  return (await signIn(nativeToken)).access_token
}

beforeAll(async () => {
  await harness.createClient({ id: 'gateway', secret: SECRET, grantTypes: ['client_credentials', 'authorization_code', EXCHANGE], redirectUris: [REDIRECT] })
  await harness.createClient({ id: 'other', secret: SECRET, grantTypes: [EXCHANGE] })
  await harness.createClient({ id: 'relay', secret: SECRET, grantTypes: ['client_credentials', 'authorization_code', 'refresh_token', EXCHANGE], redirectUris: [RELAY_REDIRECT] })
  for (const id of ['agent', 'stranger', 'retired', 'roaming']) await harness.createClient({ id, secret: SECRET, grantTypes: ['client_credentials'] })
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
    expect(await (await exchange('not-a-token')).json()).toMatchObject({ error: 'invalid_request' })
  })

  it('refuses a token that was not addressed to the client, and chains', async () => {
    // The person's own sign-in token was issued to no client.
    expect(await (await exchange(person.accessToken)).json()).toMatchObject({ error: 'invalid_request' })
    const machine = await harness.request('/api/v1/oauth/token', form({ grant_type: 'client_credentials', client_id: 'gateway', client_secret: SECRET, scope: 'gateway:read' }))
    const machineToken = ((await machine.json()) as { access_token: string }).access_token
    // A client_credentials token is no person's token.
    expect(await (await exchange(machineToken)).json()).toMatchObject({ error: 'invalid_request' })
    const delegated = ((await (await exchange(await issuedToGateway(person.accessToken))).json()) as { access_token: string }).access_token
    expect(await (await exchange(delegated)).json()).toMatchObject({ error: 'invalid_request' })
  })
})

describe('token exchange: refused subject token types', () => {
  it('refuses ID tokens and foreign token types with the reason', async () => {
    const subject = await issuedToGateway(person.accessToken)
    const idToken = await errorOf(await exchange(subject, { subject_token_type: 'urn:ietf:params:oauth:token-type:id_token' }))
    expect(idToken).toMatchObject({ error: 'invalid_request' })
    expect(idToken.error_description).toMatch(/id_token is refused.*access or refresh token/)
    expect((await errorOf(await exchange(subject, { subject_token_type: 'urn:ietf:params:oauth:token-type:saml2' }))).error_description).toMatch(/SAML/)
    expect((await errorOf(await exchange(subject, { subject_token_type: 'urn:example:custom' }))).error).toBe('invalid_request')
    expect((await errorOf(await exchange(subject, { requested_token_type: REFRESH }))).error_description).toMatch(/never comes with a refresh token/)
  })
})

describe('token exchange: refresh token subjects', () => {
  const relayExchange = (subjectToken: string, extra: Record<string, string> = {}) => exchange(subjectToken, { subject_token_type: REFRESH, ...extra }, 'relay')

  it('exchanges a refresh token issued to the client when its policy opts in, without consuming it', async () => {
    const signedIn = await signIn(person.accessToken, 'relay', RELAY_REDIRECT)
    expect(signedIn.refresh_token).toBeTruthy()
    const response = await relayExchange(signedIn.refresh_token!)
    expect(response.status).toBe(200)
    const body = (await response.json()) as { access_token: string; expires_in: number; scope: string }
    expect(body.scope).toBe('memory:read')
    expect(body.expires_in).toBeLessThanOrEqual(90)
    expect(decodeJwt(body.access_token)).toMatchObject({ sub: personId, aud: 'memory', act: { sub: 'relay' }, clientId: 'relay', sessionId: decodeJwt(signedIn.access_token)['sessionId'] })
    // The refresh token still refreshes: exchange does not rotate it.
    const refreshed = await harness.request('/api/v1/oauth/token', form({ grant_type: 'refresh_token', client_id: 'relay', client_secret: SECRET, refresh_token: signedIn.refresh_token! }))
    expect(refreshed.status).toBe(200)
    // ...and once rotated, it no longer exchanges.
    expect(await errorOf(await relayExchange(signedIn.refresh_token!))).toMatchObject({ error: 'invalid_request' })
  })

  it('refuses refresh tokens of other clients, of no client, of ended sessions, and when the policy does not opt in', async () => {
    const signedIn = await signIn(person.accessToken, 'relay', RELAY_REDIRECT)
    // gateway's policy accepts access tokens only.
    expect((await errorOf(await exchange(signedIn.refresh_token!, { subject_token_type: REFRESH }))).error_description).toMatch(/may not exchange a refresh_token/)
    // A refresh token is bound to one client: the native sign-in's has none.
    expect(await errorOf(await relayExchange(person.refreshToken))).toMatchObject({ error: 'invalid_request' })
    expect(await errorOf(await relayExchange('not-a-refresh-token'))).toMatchObject({ error: 'invalid_request' })
    // An access token presented as a refresh token is no refresh token.
    expect(await errorOf(await relayExchange(signedIn.access_token))).toMatchObject({ error: 'invalid_request' })
    const sessionId = String(decodeJwt(signedIn.access_token)['sessionId'])
    await harness.request(`/api/v1/auth/sessions/${sessionId}`, { method: 'DELETE', headers: { authorization: `Bearer ${person.accessToken}` } })
    expect(await errorOf(await relayExchange(signedIn.refresh_token!))).toMatchObject({ error: 'invalid_request' })
    person = await harness.login('kim', 'kim-fixture-password')
  })
})

describe('token exchange: actor tokens (RFC 8693 delegation)', () => {
  it('names a listed machine client as the current actor and the caller as the prior one', async () => {
    const subject = await issuedToGateway(person.accessToken)
    const actorToken = await clientCredentials('agent')
    const response = await exchange(subject, { actor_token: actorToken, actor_token_type: ACCESS })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { access_token: string; expires_in: number }
    const claims = decodeJwt(body.access_token)
    expect(claims).toMatchObject({ sub: personId, aud: 'memory', clientId: 'gateway', act: { sub: 'agent', act: { sub: 'gateway' } }, permissions: ['memory:read'] })
    expect(Number(claims.exp)).toBeLessThanOrEqual(Number(decodeJwt(actorToken).exp))
    // Introspection reports the actor chain.
    const introspected = await harness.request('/api/v1/oauth/introspect', form({ client_id: 'gateway', client_secret: SECRET, token: body.access_token }))
    expect(await introspected.json()).toMatchObject({ active: true, act: { sub: 'agent', act: { sub: 'gateway' } } })
    // The caller's own client_credentials token as actor changes nothing.
    const own = await exchange(subject, { actor_token: await clientCredentials('gateway'), actor_token_type: ACCESS })
    expect(decodeJwt(((await own.json()) as { access_token: string }).access_token).act).toEqual({ sub: 'gateway' })
  })

  it('refuses actors the policy does not list, people, delegated tokens and malformed requests', async () => {
    const subject = await issuedToGateway(person.accessToken)
    const agent = await clientCredentials('agent')
    expect((await errorOf(await exchange(subject, { actor_token: agent }))).error).toBe('invalid_request')
    expect((await errorOf(await exchange(subject, { actor_token: agent, actor_token_type: 'urn:ietf:params:oauth:token-type:id_token' }))).error).toBe('invalid_request')
    expect((await errorOf(await exchange(subject, { actor_token_type: ACCESS }))).error).toBe('invalid_request')
    // Not listed for this audience, or not listed at all.
    expect((await errorOf(await exchange(subject, { audience: 'archive', actor_token: agent, actor_token_type: ACCESS }))).error_description).toMatch(/may not name that actor/)
    expect((await errorOf(await exchange(subject, { actor_token: await clientCredentials('stranger'), actor_token_type: ACCESS }))).error_description).toMatch(/may not name that actor/)
    // Listed, but its token is addressed elsewhere.
    expect((await errorOf(await exchange(subject, { actor_token: await clientCredentials('roaming'), actor_token_type: ACCESS }))).error_description).toMatch(/not issued to this client/)
    // A person is never the actor; nor is a delegated token.
    expect((await errorOf(await exchange(subject, { actor_token: subject, actor_token_type: ACCESS }))).error_description).toMatch(/person is never the actor/)
    const delegated = ((await (await exchange(subject)).json()) as { access_token: string }).access_token
    expect((await errorOf(await exchange(subject, { actor_token: delegated, actor_token_type: ACCESS }))).error_description).toMatch(/already a delegated token/)
    expect((await errorOf(await exchange(subject, { actor_token: 'not-a-token', actor_token_type: ACCESS }))).error).toBe('invalid_request')
    // A listed actor whose client was deactivated after its token was issued.
    const retired = await clientCredentials('retired')
    await harness.prisma.client.update({ where: { id: 'retired' }, data: { active: false } })
    expect((await errorOf(await exchange(subject, { actor_token: retired, actor_token_type: ACCESS }))).error).toBe('invalid_request')
  })
})

describe('token exchange: audit and verification', () => {
  it('audits every exchange, granted or refused, without token values', async () => {
    auditEvents.length = 0
    const subject = await issuedToGateway(person.accessToken)
    await exchange(subject)
    await exchange(subject, { audience: 'billing' })
    const granted = auditEvents.find((event) => event.eventType === 'oauth.token_exchange_delegated')
    const refused = auditEvents.find((event) => event.eventType === 'oauth.token_exchange_refused')
    expect(granted).toMatchObject({ outcome: 'SUCCESS', clientId: 'gateway', actorId: personId, detail: { audience: 'memory', subjectTokenType: 'access_token', act: { sub: 'gateway' } } })
    expect(refused).toMatchObject({ outcome: 'DENIED', clientId: 'gateway', detail: { error: 'invalid_target', audience: 'billing', subjectTokenType: ACCESS } })
    expect(JSON.stringify(auditEvents)).not.toContain(subject)
  })

  it('refuses a token whose act claim Oathweave would never issue, even when signed', async () => {
    const key = await importPKCS8(readFileSync(join(harness.directory, 'private.pem'), 'utf8'), 'RS256')
    const issued = await issuedToGateway(person.accessToken)
    const { kid } = decodeProtectedHeader(issued)
    const subject = decodeJwt(issued)
    const forge = (act: unknown) => new SignJWT({ actorType: 'USER', roles: [], permissions: ['memory:read'], sessionId: subject['sessionId'], clientId: 'gateway', act })
      .setProtectedHeader({ alg: 'RS256', kid: kid! }).setSubject(personId).setIssuer(String(subject.iss)).setAudience('memory').setIssuedAt().setExpirationTime('2m').setJti('fixture-token').sign(key)
    const introspect = async (token: string) => (await (await harness.request('/api/v1/oauth/introspect', form({ client_id: 'gateway', client_secret: SECRET, token }))).json()) as { active: boolean }
    expect((await introspect(await forge({ sub: 'gateway' }))).active).toBe(true)
    for (const act of ['gateway', { sub: '' }, { sub: 'a', act: { sub: 'b', act: { sub: 'c' } } }, { sub: 'a', extra: true }, []]) {
      expect((await introspect(await forge(act))).active).toBe(false)
    }
  })
})
