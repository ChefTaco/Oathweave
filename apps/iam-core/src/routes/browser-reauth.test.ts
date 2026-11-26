/**
 * Re-authentication through the browser authorization endpoint, against the real server:
 * `prompt=login` always needs a sign-in completed for the request (a live SSO session alone
 * never satisfies it), `max_age` reuses only a recent enough session, `prompt=none` and a
 * cancelled sign-in return an OAuth error for the client's callback, and the ID token's
 * `auth_time` is the time of the sign-in (or step-up) that the code was issued for.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { createLocalJWKSet, decodeJwt, jwtVerify, type JWTPayload } from 'jose'
import { createHash, randomBytes } from 'node:crypto'
import { Secret, TOTP } from 'otpauth'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const ISSUER = 'https://identity.example.com'
const ORIGIN = 'https://console.example.com'
const CALLBACK = `${ORIGIN}/auth/callback`
const RP = { rpId: 'identity.example.com', origin: 'https://identity.example.com' }
const FIRST_PARTY = 'hivexui-oathweave'
const THIRD_PARTY = 'hivexui-partner'
const { startRealApp } = await import('../test-support/real-app.js')
const { softPasskey } = await import('../test-support/soft-authenticator.js')
const { resetFakeRedis } = await import('../test-support/fake-redis.js')
const harness = await startRealApp({
  JWT_ISSUER: ISSUER,
  IAM_PUBLIC_URL: ISSUER,
  IAM_BROWSER_ISSUER: ISSUER,
  IAM_BROWSER_CLIENT_POLICIES: JSON.stringify({
    [FIRST_PARTY]: { audience: 'oathweave', permissions: ['iam:users:read'] },
    [THIRD_PARTY]: { audience: 'partner', permissions: ['iam:users:read'] },
  }),
  WEBAUTHN_RP_ID: RP.rpId,
  WEBAUTHN_RP_ORIGIN: RP.origin,
})

const browserHeaders = { 'content-type': 'application/json', origin: ORIGIN, 'x-oathweave-browser': 'true' }
const post = (path: string, body: unknown, cookie?: string) =>
  harness.request(`/api/v1${path}`, {
    method: 'POST',
    headers: { ...browserHeaders, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  })

function ssoCookie(response: Response): string {
  const header = response.headers.get('set-cookie') ?? ''
  const match = /__Host-oathweave_sso=([^;]+)/.exec(header)
  if (!match) throw new Error(`no SSO cookie (status ${response.status})`)
  return `__Host-oathweave_sso=${match[1]}`
}
const sessionOf = (cookie: string) => decodeJwt(cookie.split('=')[1]!).sessionId as string

const password = 'reauth-fixture-password'
const totpSecret = new Secret({ size: 20 }).base32
const totpNow = () => new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(totpSecret) }).generate()
const recoveryCode = 'rcvy1234'
const passkey = softPasskey()
const secondFactorKey = softPasskey()

beforeAll(async () => {
  for (const id of [FIRST_PARTY, THIRD_PARTY])
    await harness.createClient({ id, clientType: 'public', grantTypes: ['authorization_code'], redirectUris: [CALLBACK], firstParty: id === FIRST_PARTY })
  const roles = [{ name: 'viewer', permissions: ['iam:users:read'] }]
  await harness.createUser({ username: 'pat', password, roles })
  const totp = await harness.createUser({ username: 'tess', password, roles })
  await harness.prisma.user.update({
    where: { id: totp.id },
    data: { mfaEnabled: true, mfaSecret: totpSecret, mfaVerifiedAt: new Date(), mfaBackupCodes: JSON.stringify([await harness.hashSecret(recoveryCode)]) },
  })
  const passwordless = await harness.createUser({ username: 'paula', password, roles })
  await harness.prisma.webAuthnCredential.create({
    data: { id: 'reauth-passkey', userId: passwordless.id, credentialId: passkey.credentialId, publicKey: passkey.publicKey, counter: 0, deviceType: 'multiDevice', backedUp: true, transports: '["internal"]', friendlyName: 'Phone' },
  })
  await harness.prisma.user.update({ where: { id: passwordless.id }, data: { mfaEnabled: true } })
  const secondFactor = await harness.createUser({ username: 'kim', password, roles })
  await harness.prisma.webAuthnCredential.create({
    data: { id: 'reauth-second-factor', userId: secondFactor.id, credentialId: secondFactorKey.credentialId, publicKey: secondFactorKey.publicKey, counter: 0, deviceType: 'singleDevice', backedUp: false, transports: '["usb"]', friendlyName: 'Key' },
  })
  await harness.prisma.user.update({ where: { id: secondFactor.id }, data: { mfaEnabled: true } })
})

// Fresh sign-in throttles and TOTP step claims for every case.
beforeEach(() => resetFakeRedis())

/** Password sign-in through the browser boundary; returns the SSO cookie or the MFA challenge. */
async function passwordLogin(username: string): Promise<{ cookie?: string; mfaToken?: string }> {
  const response = await post('/auth/login', { username, password })
  expect(response.status).toBe(200)
  const body = (await response.clone().json()) as { requiresMfa?: boolean; mfaToken?: string }
  if (body.requiresMfa) return { mfaToken: body.mfaToken! }
  return { cookie: ssoCookie(response) }
}
async function signIn(username = 'pat'): Promise<string> {
  const { cookie } = await passwordLogin(username)
  return cookie!
}
async function completeMfa(mfaToken: string, code: string): Promise<string> {
  const response = await post('/auth/mfa/challenge', { mfaToken, code })
  expect(response.status).toBe(200)
  return ssoCookie(response)
}
let passkeyCounter = 0
async function passwordlessSignIn(): Promise<string> {
  const options = (await (await post('/mfa/webauthn/passwordless/options', {})).json()) as { ceremonyId: string; data: { challenge: string } }
  const response = await post('/mfa/webauthn/passwordless/authenticate', {
    ceremonyId: options.ceremonyId,
    response: passkey.assert({ ...RP, challenge: options.data.challenge, counter: ++passkeyCounter }),
  })
  expect(response.status).toBe(200)
  return ssoCookie(response)
}
let secondFactorCounter = 0
async function passkeySecondFactor(mfaToken: string): Promise<string> {
  const options = (await (await post('/mfa/webauthn/authenticate-options', { mfaToken })).json()) as { data: { challenge: string } }
  const response = await post('/mfa/webauthn/authenticate', {
    mfaToken,
    response: secondFactorKey.assert({ ...RP, challenge: options.data.challenge, counter: ++secondFactorCounter }),
  })
  expect(response.status).toBe(200)
  return ssoCookie(response)
}

/** Move a session's sign-in into the past, as if it had been live for `seconds`. */
async function age(cookie: string, seconds: number): Promise<Date> {
  const createdAt = new Date(Date.now() - seconds * 1000)
  await harness.prisma.session.update({ where: { id: sessionOf(cookie) }, data: { createdAt } })
  return createdAt
}

function request(clientId = FIRST_PARTY, extra: Record<string, unknown> = {}) {
  const verifier = randomBytes(32).toString('base64url')
  return {
    verifier,
    body: {
      clientId,
      redirectUri: CALLBACK,
      responseType: 'code',
      codeChallenge: createHash('sha256').update(verifier).digest('base64url'),
      codeChallengeMethod: 'S256',
      scope: 'openid profile',
      state: randomBytes(24).toString('base64url'),
      nonce: randomBytes(24).toString('base64url'),
      ...extra,
    },
  }
}

async function idToken(code: string, verifier: string, clientId = FIRST_PARTY): Promise<JWTPayload> {
  const response = await post('/oauth/token', { grant_type: 'authorization_code', client_id: clientId, code, code_verifier: verifier, redirect_uri: CALLBACK })
  expect(response.status).toBe(200)
  const { id_token } = (await response.json()) as { id_token: string }
  const jwks = (await (await harness.request('/api/v1/oauth/jwks')).json()) as Parameters<typeof createLocalJWKSet>[0]
  return (await jwtVerify(id_token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: clientId })).payload
}

type LoginRequired = { error: string; reason: string; loginTicket: string; loginTicketExpiresIn: number }
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

describe('without prompt or max_age', () => {
  it('reuses the live SSO session; auth_time is that sign-in and the nonce is echoed', async () => {
    const cookie = await signIn()
    const signedInAt = await age(cookie, 3600)
    const { body, verifier } = request()
    const response = await post('/oauth/authorize', body, cookie)
    expect(response.status).toBe(200)
    const { code, state, iss } = (await response.json()) as { code: string; state: string; iss: string }
    expect({ state, iss }).toEqual({ state: body.state, iss: ISSUER })
    const claims = await idToken(code, verifier)
    expect(claims).toMatchObject({ auth_time: seconds(signedInAt), nonce: body.nonce, sid: sessionOf(cookie) })
    expect(claims.amr).toBeUndefined()
    expect(claims.acr).toBeUndefined()
  })

  it('answers LOGIN_REQUIRED with a login ticket when there is no sign-in', async () => {
    const response = await post('/oauth/authorize', request().body)
    expect(response.status).toBe(401)
    expect(await response.json()).toMatchObject({ error: 'LOGIN_REQUIRED', reason: 'no_session', loginTicket: expect.any(String), loginTicketExpiresIn: 600 })
  })
})

describe('prompt=login', () => {
  it('refuses a live SSO session, even with the ticket, until a sign-in after the ticket', async () => {
    const original = await signIn()
    await age(original, 3600)
    const { body, verifier } = request(FIRST_PARTY, { prompt: 'login' })
    const first = await post('/oauth/authorize', body, original)
    expect(first.status).toBe(401)
    const required = (await first.json()) as LoginRequired
    expect(required).toMatchObject({ error: 'LOGIN_REQUIRED', reason: 'prompt_login' })

    // The live session cannot simply repeat the request with the ticket.
    const replay = await post('/oauth/authorize', { ...body, loginTicket: required.loginTicket }, original)
    expect(replay.status).toBe(401)
    expect(await replay.json()).toMatchObject({ reason: 'prompt_login' })

    const fresh = await signIn()
    const freshSession = await harness.prisma.session.findUniqueOrThrow({ where: { id: sessionOf(fresh) } })
    const approved = await post('/oauth/authorize', { ...body, loginTicket: required.loginTicket }, fresh)
    expect(approved.status).toBe(200)
    const { code } = (await approved.json()) as { code: string }
    const claims = await idToken(code, verifier)
    expect(claims.auth_time).toBe(seconds(freshSession.createdAt))
    expect(claims.auth_time).toBeGreaterThanOrEqual(Math.floor(decodeJwt(required.loginTicket).iat!))
    expect(claims).toMatchObject({ nonce: body.nonce, sid: sessionOf(fresh) })
  })

  it('without a ticket a fresh sign-in is still not enough', async () => {
    const cookie = await signIn()
    const response = await post('/oauth/authorize', request(FIRST_PARTY, { prompt: 'login' }).body, cookie)
    expect(response.status).toBe(401)
  })

  it('binds the ticket to the exact request', async () => {
    const { body } = request(FIRST_PARTY, { prompt: 'login' })
    const { loginTicket } = (await (await post('/oauth/authorize', body)).json()) as LoginRequired
    const cookie = await signIn()
    const other = request(FIRST_PARTY, { prompt: 'login', loginTicket }).body
    expect((await post('/oauth/authorize', other, cookie)).status).toBe(401)
    expect((await post('/oauth/authorize', { ...body, loginTicket: loginTicket.slice(0, -4) + 'AAAA' }, cookie)).status).toBe(401)
    expect((await post('/oauth/authorize', { ...body, loginTicket }, cookie)).status).toBe(200)
  })

  it('treats select_account as a forced sign-in too', async () => {
    const cookie = await signIn()
    expect((await post('/oauth/authorize', request(FIRST_PARTY, { prompt: 'select_account' }).body, cookie)).status).toBe(401)
  })

  async function forcedSignIn(signInNow: () => Promise<string>) {
    const live = await signIn()
    await age(live, 3600)
    const { body, verifier } = request(FIRST_PARTY, { prompt: 'login' })
    const first = await post('/oauth/authorize', body, live)
    expect(first.status).toBe(401)
    const { loginTicket } = (await first.json()) as LoginRequired
    const fresh = await signInNow()
    const session = await harness.prisma.session.findUniqueOrThrow({ where: { id: sessionOf(fresh) } })
    const response = await post('/oauth/authorize', { ...body, loginTicket }, fresh)
    expect(response.status).toBe(200)
    const claims = await idToken(((await response.json()) as { code: string }).code, verifier)
    expect(claims.auth_time).toBe(seconds(session.createdAt))
    expect(claims.nonce).toBe(body.nonce)
    return claims
  }

  it('accepts a password and TOTP sign-in', async () => {
    await forcedSignIn(async () => completeMfa((await passwordLogin('tess')).mfaToken!, totpNow()))
  })

  it('accepts a password and recovery code sign-in', async () => {
    await forcedSignIn(async () => completeMfa((await passwordLogin('tess')).mfaToken!, recoveryCode))
  })

  it('accepts a password and passkey sign-in', async () => {
    await forcedSignIn(async () => passkeySecondFactor((await passwordLogin('kim')).mfaToken!))
  })

  it('accepts a passwordless passkey sign-in', async () => {
    await forcedSignIn(passwordlessSignIn)
  })

  it('asks for consent after the forced sign-in for a client that needs it', async () => {
    const { body, verifier } = request(THIRD_PARTY, { prompt: 'login' })
    const { loginTicket } = (await (await post('/oauth/authorize', body)).json()) as LoginRequired
    const cookie = await signIn()
    const consent = await post('/oauth/authorize', { ...body, loginTicket }, cookie)
    expect(consent.status).toBe(403)
    expect(await consent.json()).toMatchObject({ error: 'CONSENT_REQUIRED' })
    const approved = await post('/oauth/authorize', { ...body, loginTicket, consent: 'approve' }, cookie)
    expect(approved.status).toBe(200)
    await idToken(((await approved.json()) as { code: string }).code, verifier, THIRD_PARTY)
  })
})

describe('max_age', () => {
  it('reuses a session that is recent enough, with its original auth_time', async () => {
    const cookie = await signIn()
    const signedInAt = await age(cookie, 600)
    const { body, verifier } = request(FIRST_PARTY, { maxAge: 3600 })
    const response = await post('/oauth/authorize', body, cookie)
    expect(response.status).toBe(200)
    expect((await idToken(((await response.json()) as { code: string }).code, verifier)).auth_time).toBe(seconds(signedInAt))
  })

  it('asks for a sign-in when the session is older, then issues the new auth_time', async () => {
    const cookie = await signIn()
    const signedInAt = await age(cookie, 600)
    const { body, verifier } = request(FIRST_PARTY, { maxAge: 60 })
    const first = await post('/oauth/authorize', body, cookie)
    expect(first.status).toBe(401)
    const { reason, loginTicket } = (await first.json()) as LoginRequired
    expect(reason).toBe('max_age')
    const fresh = await signIn()
    const response = await post('/oauth/authorize', { ...body, loginTicket }, fresh)
    expect(response.status).toBe(200)
    const claims = await idToken(((await response.json()) as { code: string }).code, verifier)
    expect(claims.auth_time).toBeGreaterThan(seconds(signedInAt) + 500)
    expect(Math.floor(Date.now() / 1000) - (claims.auth_time as number)).toBeLessThanOrEqual(60)
  })

  it('max_age=0 needs a sign-in for this request, like prompt=login', async () => {
    const live = await signIn()
    const { body } = request(FIRST_PARTY, { maxAge: 0 })
    const first = await post('/oauth/authorize', body, live)
    expect(first.status).toBe(401)
    const { loginTicket } = (await first.json()) as LoginRequired
    expect((await post('/oauth/authorize', { ...body, loginTicket }, await signIn())).status).toBe(200)
  })

  it('counts a step-up verification as the latest authentication', async () => {
    const cookie = await signIn()
    await age(cookie, 600)
    const stepUp = await post('/auth/step-up', { password }, cookie)
    expect(stepUp.status).toBe(200)
    const { body, verifier } = request(FIRST_PARTY, { maxAge: 60 })
    const response = await post('/oauth/authorize', body, cookie)
    expect(response.status).toBe(200)
    const session = await harness.prisma.session.findUniqueOrThrow({ where: { id: sessionOf(cookie) } })
    expect((await idToken(((await response.json()) as { code: string }).code, verifier)).auth_time).toBe(seconds(session.stepUpVerifiedAt!))
  })
})

describe('prompt=none', () => {
  type ErrorResponse = { error: string; state: string; iss: string; redirectTo: string }
  function expectCallback(result: ErrorResponse, error: string, state: string) {
    expect(result).toMatchObject({ error, state, iss: ISSUER })
    const url = new URL(result.redirectTo)
    expect(url.origin + url.pathname).toBe(CALLBACK)
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ error, state, iss: ISSUER })
  }

  it('returns login_required for the callback without a sign-in', async () => {
    const { body } = request(FIRST_PARTY, { prompt: 'none' })
    const response = await post('/oauth/authorize', body)
    expect(response.status).toBe(400)
    expectCallback((await response.json()) as ErrorResponse, 'login_required', body.state)
  })

  it('returns login_required when max_age has expired', async () => {
    const cookie = await signIn()
    await age(cookie, 600)
    const { body } = request(FIRST_PARTY, { prompt: 'none', maxAge: 60 })
    const response = await post('/oauth/authorize', body, cookie)
    expect(response.status).toBe(400)
    expectCallback((await response.json()) as ErrorResponse, 'login_required', body.state)
  })

  it('issues a code silently for a live session, and consent_required where consent is needed', async () => {
    const cookie = await signIn()
    expect((await post('/oauth/authorize', request(FIRST_PARTY, { prompt: 'none' }).body, cookie)).status).toBe(200)
    const { body } = request(THIRD_PARTY, { prompt: 'none' })
    const response = await post('/oauth/authorize', body, cookie)
    expect(response.status).toBe(400)
    expectCallback((await response.json()) as ErrorResponse, 'consent_required', body.state)
  })

  it('refuses none combined with another value', async () => {
    expect((await post('/oauth/authorize', request(FIRST_PARTY, { prompt: 'none login' }).body)).status).toBe(400)
    expect((await post('/oauth/authorize', request(FIRST_PARTY, { prompt: 'create' }).body)).status).toBe(400)
  })

  it('redirects the native GET request to the callback with the error', async () => {
    const { body } = request(FIRST_PARTY)
    const query = new URLSearchParams({ client_id: body.clientId, redirect_uri: body.redirectUri, response_type: 'code', code_challenge: body.codeChallenge, code_challenge_method: 'S256', scope: body.scope, state: body.state, nonce: body.nonce, prompt: 'none' })
    const response = await harness.request(`/api/v1/oauth/authorize?${query}`)
    expect(response.status).toBe(302)
    const url = new URL(response.headers.get('location')!)
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ error: 'login_required', state: body.state, iss: ISSUER })
  })
})

describe('a cancelled or declined authorization', () => {
  it('cancel returns access_denied with the state for the registered callback, without a sign-in', async () => {
    const { body } = request()
    const response = await post('/oauth/authorize/cancel', body)
    expect(response.status).toBe(200)
    const result = (await response.json()) as { error: string; state: string; iss: string; redirectTo: string }
    expect(result).toMatchObject({ error: 'access_denied', state: body.state, iss: ISSUER })
    expect(Object.fromEntries(new URL(result.redirectTo).searchParams)).toMatchObject({ error: 'access_denied', state: body.state, iss: ISSUER })
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  it('cancel refuses an unregistered callback, an unknown client and a non-browser caller', async () => {
    const { body } = request()
    expect((await post('/oauth/authorize/cancel', { ...body, redirectUri: 'https://evil.example.net/callback' })).status).toBe(400)
    expect((await post('/oauth/authorize/cancel', { ...body, clientId: 'hivexui-unknown' })).status).toBe(400)
    const native = await harness.request('/api/v1/oauth/authorize/cancel', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify(body) })
    expect(native.status).toBe(400)
    const foreign = await harness.request('/api/v1/oauth/authorize/cancel', { method: 'POST', headers: { ...browserHeaders, origin: 'https://evil.example.net' }, body: JSON.stringify(body) })
    expect(foreign.status).toBe(403)
  })

  it('declining consent carries the access_denied callback', async () => {
    const cookie = await signIn()
    const { body } = request(THIRD_PARTY)
    const response = await post('/oauth/authorize', { ...body, consent: 'deny' }, cookie)
    expect(response.status).toBe(403)
    const result = (await response.json()) as { error: string; redirectTo: string }
    expect(result.error).toBe('ACCESS_DENIED')
    expect(Object.fromEntries(new URL(result.redirectTo).searchParams)).toMatchObject({ error: 'access_denied', state: body.state, iss: ISSUER })
  })
})

describe('discovery', () => {
  it('advertises the prompt values', async () => {
    const native = (await (await harness.request('/.well-known/openid-configuration')).json()) as { prompt_values_supported: string[] }
    expect(native.prompt_values_supported).toEqual(['none', 'login', 'consent', 'select_account'])
  })
})
