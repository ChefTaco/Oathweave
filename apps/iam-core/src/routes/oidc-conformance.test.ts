/**
 * A generic relying party (oauth4webapi, which validates responses strictly against the OAuth 2.0
 * and OpenID Connect specifications) against the real server: discovery at the issuer, the
 * authorization code flow with PKCE and client_secret_basic, the id_token, UserInfo, refresh,
 * introspection, revocation and RP-initiated logout.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
import * as oauth from 'oauth4webapi'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const ISSUER = 'https://identity.example.com'
const { startRealApp } = await import('../test-support/real-app.js')
const harness = await startRealApp({ JWT_ISSUER: ISSUER, IAM_PUBLIC_URL: ISSUER })

const fetchOptions = {
  [oauth.customFetch]: (url: string, init: RequestInit) => {
    const target = new URL(url)
    return harness.request(target.pathname + target.search, init)
  },
}
const REDIRECT = 'https://rp.example.com/callback'
const SECRET = 'conformance-rp-secret-'.padEnd(43, 'q')
const client: oauth.Client = { client_id: 'conformance-rp' }
const clientAuth = oauth.ClientSecretBasic(SECRET)
let as: oauth.AuthorizationServer
let user: { accessToken: string; sessionId: string }

beforeAll(async () => {
  await harness.createClient({ id: 'conformance-rp', secret: SECRET, grantTypes: ['authorization_code', 'refresh_token'], redirectUris: [REDIRECT] })
  await harness.createUser({ username: 'grace', password: 'grace-fixture-password', email: 'grace@example.com', roles: [{ name: 'viewer', permissions: ['iam:users:read'] }] })
  user = await harness.login('grace', 'grace-fixture-password')
  as = await oauth.processDiscoveryResponse(new URL(ISSUER), await oauth.discoveryRequest(new URL(ISSUER), fetchOptions))
})

/** The user approves on the native consent route; the relying party receives the redirect. */
async function authorize(scope: string) {
  const verifier = oauth.generateRandomCodeVerifier()
  const state = oauth.generateRandomState()
  const nonce = oauth.generateRandomNonce()
  const response = await harness.request('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { authorization: `Bearer ${user.accessToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      clientId: client.client_id, redirectUri: REDIRECT, responseType: 'code', scope, state, nonce, consent: 'approve',
      codeChallenge: await oauth.calculatePKCECodeChallenge(verifier), codeChallengeMethod: 'S256',
    }),
  })
  expect(response.status).toBe(200)
  const { redirectUri } = (await response.json()) as { redirectUri: string }
  const params = oauth.validateAuthResponse(as, client, new URL(redirectUri), state)
  const tokens = await oauth.processAuthorizationCodeResponse(
    as, client,
    await oauth.authorizationCodeGrantRequest(as, client, clientAuth, params, REDIRECT, verifier, fetchOptions),
    { expectedNonce: nonce, requireIdToken: true },
  )
  return tokens
}

describe('a generic OpenID Connect relying party', () => {
  it('discovers the issuer at its own well-known path', () => {
    expect(as).toMatchObject({
      issuer: ISSUER,
      token_endpoint: `${ISSUER}/api/v1/oauth/token`,
      revocation_endpoint: `${ISSUER}/api/v1/oauth/revoke`,
      introspection_endpoint: `${ISSUER}/api/v1/oauth/introspect`,
      end_session_endpoint: `${ISSUER}/api/v1/oauth/logout`,
    })
    expect(as.claims_supported).toEqual(expect.arrayContaining(['preferred_username', 'email_verified', 'auth_time', 'sid']))
    expect(as.claims_supported).not.toContain('username')
  })

  it('completes the code flow and gets a valid id_token with auth_time, sid and scoped claims', async () => {
    const tokens = await authorize('openid profile email')
    const claims = oauth.getValidatedIdTokenClaims(tokens)!
    expect(claims).toMatchObject({ iss: ISSUER, aud: 'conformance-rp', preferred_username: 'grace', email: 'grace@example.com', email_verified: false })
    expect(typeof claims.auth_time).toBe('number')
    expect(typeof claims['sid']).toBe('string')
    expect(tokens.scope).toBe('openid profile email')

    const info = await oauth.processUserInfoResponse(as, client, claims.sub, await oauth.userInfoRequest(as, client, tokens.access_token, fetchOptions))
    expect(info).toMatchObject({ sub: claims.sub, preferred_username: 'grace', email: 'grace@example.com', email_verified: false, roles: ['viewer'] })
  })

  it('returns only the claims the scope asks for, and keeps the scope across refresh', async () => {
    const tokens = await authorize('openid')
    const claims = oauth.getValidatedIdTokenClaims(tokens)!
    expect(claims.email).toBeUndefined()
    expect(claims.preferred_username).toBeUndefined()
    const info = await oauth.processUserInfoResponse(as, client, claims.sub, await oauth.userInfoRequest(as, client, tokens.access_token, fetchOptions))
    expect(info.email).toBeUndefined()
    expect(info.preferred_username).toBeUndefined()

    const refreshed = await oauth.processRefreshTokenResponse(as, client, await oauth.refreshTokenGrantRequest(as, client, clientAuth, tokens.refresh_token!, fetchOptions))
    const after = await oauth.processUserInfoResponse(as, client, claims.sub, await oauth.userInfoRequest(as, client, refreshed.access_token, fetchOptions))
    expect(after.email).toBeUndefined()
  })

  it('introspects and revokes its own tokens at the advertised endpoints', async () => {
    const tokens = await authorize('openid profile')
    const active = await oauth.processIntrospectionResponse(as, client, await oauth.introspectionRequest(as, client, clientAuth, tokens.access_token, fetchOptions))
    expect(active).toMatchObject({ active: true, client_id: 'conformance-rp', iss: ISSUER, scope: 'openid profile' })

    await oauth.processRevocationResponse(await oauth.revocationRequest(as, client, clientAuth, tokens.refresh_token!, { ...fetchOptions, additionalParameters: { token_type_hint: 'refresh_token' } }))
    const refresh = await oauth.refreshTokenGrantRequest(as, client, clientAuth, tokens.refresh_token!, fetchOptions)
    await expect(oauth.processRefreshTokenResponse(as, client, refresh)).rejects.toThrow()
  })

  it('signs out through end_session_endpoint and returns to a registered address', async () => {
    const tokens = await authorize('openid')
    const logout = new URL(as.end_session_endpoint!)
    logout.searchParams.set('id_token_hint', tokens.id_token!)
    logout.searchParams.set('post_logout_redirect_uri', REDIRECT)
    logout.searchParams.set('state', 'fixture-state')
    const response = await harness.request(logout.pathname + logout.search)
    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toBe(`${REDIRECT}?state=fixture-state`)
    const info = await oauth.userInfoRequest(as, client, tokens.access_token, fetchOptions)
    expect(info.status).toBe(401)

    const unregistered = new URL(as.end_session_endpoint!)
    unregistered.searchParams.set('client_id', 'conformance-rp')
    unregistered.searchParams.set('post_logout_redirect_uri', 'https://attacker.example.com/')
    expect((await harness.request(unregistered.pathname + unregistered.search)).status).toBe(400)
    const forged = new URL(as.end_session_endpoint!)
    // An unsigned token naming a subject: built here so no token-shaped literal is committed.
    const unsigned = [{ alg: 'none' }, { sub: 'x', iss: ISSUER }].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.') + '.'
    forged.searchParams.set('id_token_hint', unsigned)
    expect((await harness.request(forged.pathname + forged.search)).status).toBe(400)
  })
})

describe('an access token issued to a relying party', () => {
  const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>
  const bearer = (token: string, init: RequestInit = {}) => ({ ...init, headers: { ...(init.headers as Record<string, string>), authorization: `Bearer ${token}` } })

  it('is addressed to that client, not to Oathweave', async () => {
    const tokens = await authorize('openid profile')
    expect(claimsOf(tokens.access_token)).toMatchObject({ aud: 'conformance-rp', clientId: 'conformance-rp' })
    expect(claimsOf(user.accessToken).aud).toBeUndefined()
  })

  it('cannot call the management API even when the person may', async () => {
    const tokens = await authorize('openid profile')
    // The person's own native token reads users; the relying party's copy of their grants does not.
    expect((await harness.request('/api/v1/users', bearer(user.accessToken))).status).toBe(200)
    for (const [path, init] of [
      ['/api/v1/users', {}],
      ['/api/v1/auth/me', {}],
      ['/api/v1/auth/sessions', {}],
      ['/api/v1/oauth/authorize', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ clientId: 'conformance-rp', redirectUri: REDIRECT, responseType: 'code', consent: 'approve' }) }],
    ] as const) {
      const response = await harness.request(path, bearer(tokens.access_token, init))
      expect(response.status, path).toBe(401)
      expect(await response.json()).toMatchObject({ error: 'INVALID_AUDIENCE' })
    }
  })

  it('still reaches UserInfo and signs its own session out', async () => {
    const tokens = await authorize('openid profile')
    expect((await harness.request('/api/v1/oauth/userinfo', bearer(tokens.access_token))).status).toBe(200)
    expect((await harness.request('/api/v1/auth/logout', bearer(tokens.access_token, { method: 'POST' }))).status).toBe(200)
    expect((await harness.request('/api/v1/oauth/userinfo', bearer(tokens.access_token))).status).toBe(401)
  })
})

describe('self-service sessions', () => {
  it('lists and ends only the caller’s own sessions', async () => {
    const second = await harness.login('grace', 'grace-fixture-password')
    await harness.createUser({ username: 'heidi', password: 'heidi-fixture-password' })
    const other = await harness.login('heidi', 'heidi-fixture-password')
    const asGrace = { headers: { authorization: `Bearer ${second.accessToken}` } }
    const listed = (await (await harness.request('/api/v1/auth/sessions', asGrace)).json()) as { sessions: { id: string; current: boolean }[] }
    expect(listed.sessions.find((session) => session.current)?.id).toBe(second.sessionId)
    expect(listed.sessions.map((session) => session.id)).toContain(user.sessionId)
    expect(listed.sessions.map((session) => session.id)).not.toContain(other.sessionId)

    expect((await harness.request(`/api/v1/auth/sessions/${other.sessionId}`, { method: 'DELETE', ...asGrace })).status).toBe(404)
    expect((await harness.request('/api/v1/auth/me', { headers: { authorization: `Bearer ${other.accessToken}` } })).status).toBe(200)
    const ended = await harness.request(`/api/v1/auth/sessions/${user.sessionId}`, { method: 'DELETE', ...asGrace })
    expect(ended.status).toBe(200)
    expect((await harness.request('/api/v1/auth/me', { headers: { authorization: `Bearer ${user.accessToken}` } })).status).toBe(401)
  })
})
