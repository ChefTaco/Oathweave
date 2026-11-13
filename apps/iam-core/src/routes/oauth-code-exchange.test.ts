/**
 * POST /oauth/token, grant authorization_code: every exchange is bound to the client the code was
 * issued to. The real route and service run against an in-memory store.
 */
import { createHash } from 'node:crypto'
import { Hono } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { errorHandler } from '../middleware/error-handler.js'

interface StoredClient {
  id: string
  name: string
  description: null
  active: boolean
  clientType: string
  secretHash: string | null
  redirectUris: string
  grantTypes: string
  firstParty: boolean
}
interface StoredCode {
  id: string
  code: string
  clientId: string
  userId: string
  redirectUri: string
  scope: string | null
  codeChallenge: string | null
  state: string | null
  nonce: string | null
  browserSessionId: string | null
  expiresAt: Date
  usedAt: Date | null
}

const store = vi.hoisted(() => ({
  clients: new Map<string, unknown>(),
  codes: new Map<string, unknown>(),
  issued: [] as string[],
  audits: [] as string[],
}))
const clients = store.clients as Map<string, StoredClient>
const codes = store.codes as Map<string, StoredCode>

vi.mock('argon2', () => ({
  default: { verify: async (hash: string, secret: string) => hash === `hash:${secret}` },
}))
vi.mock('../config/env.js', () => ({ env: { JWT_ISSUER: 'https://identity.example.com' } }))
vi.mock('../utils/keys.js', () => ({ getPublishedSigningJwks: async () => ({ keys: [] }) }))
vi.mock('../middleware/auth.js', () => ({ authMiddleware: async () => undefined }))
vi.mock('../middleware/browser-session.js', () => ({
  requireBrowserOrigin: vi.fn(),
  browserAuthorization: async () => undefined,
}))
vi.mock('../services/browser-discovery.js', () => ({ getBrowserOpenIdConfiguration: vi.fn() }))
vi.mock('../services/session-service.js', () => ({
  createSession: async () => ({ sessionId: 'fake-session' }),
}))
vi.mock('../services/audit-service.js', () => ({
  logAuditEvent: async (event: { eventType: string }) => void store.audits.push(event.eventType),
}))
vi.mock('../services/token-service.js', () => ({
  rotateRefreshToken: vi.fn(),
  issueIdToken: async () => 'fake-id-token',
  issueTokenPair: async (...args: unknown[]) => {
    store.issued.push(String(args[7]))
    return { accessToken: 'fake-access', refreshToken: 'fake-refresh', expiresIn: 900 }
  },
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    client: {
      findUnique: async ({ where }: { where: { id: string } }) => store.clients.get(where.id) ?? null,
    },
    authorizationCode: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `id-${store.codes.size}`, usedAt: null, ...data }
        store.codes.set(String(data['code']), row)
        return row
      },
      findUnique: async ({ where }: { where: { code: string } }) => {
        const row = store.codes.get(where.code) as { clientId: string } | undefined
        if (!row) return null
        return {
          ...row,
          client: store.clients.get(row.clientId),
          user: { active: true, email: 'alice@example.com', username: 'alice', displayName: 'Alice', roles: [] },
        }
      },
      updateMany: async ({ where }: { where: { id: string } }) => {
        const row = [...store.codes.values()].find((entry) => (entry as { id: string }).id === where.id) as
          | { usedAt: Date | null }
          | undefined
        if (!row || row.usedAt) return { count: 0 }
        row.usedAt = new Date()
        return { count: 1 }
      },
      delete: async () => undefined,
    },
    session: { findFirst: async () => null },
    refreshToken: { deleteMany: async () => ({ count: 0 }) },
  },
}))

const { oauthRouter } = await import('./oauth.js')
const { createAuthorizationCode, validateAuthorizeRequest } = await import('../services/oauth-service.js')
const app = new Hono().route('/oauth', oauthRouter).onError(errorHandler)

const redirectUri = 'https://client.example.com/callback'
const secret = 'fake-client-secret-0123456789abcdef'
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const challenge = createHash('sha256').update(verifier).digest('base64url')

function register(id: string, clientType: string, secretHash: string | null) {
  clients.set(id, {
    id, name: id, description: null, active: true, clientType, secretHash,
    redirectUris: JSON.stringify([redirectUri]), grantTypes: '["authorization_code","refresh_token"]', firstParty: true,
  })
}
/** Issues a code through the real authorize path. */
async function authorize(clientId: string, pkce: boolean): Promise<string> {
  const result = await createAuthorizationCode('fake-user', {
    clientId, redirectUri, responseType: 'code', scope: 'openid',
    ...(pkce ? { codeChallenge: challenge, codeChallengeMethod: 'S256' } : {}),
  })
  return result.code
}
async function exchange(fields: Record<string, string>, init: { form?: boolean; basic?: string } = {}) {
  const body = { grant_type: 'authorization_code', redirect_uri: redirectUri, ...fields }
  const response = await app.request('/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': init.form ? 'application/x-www-form-urlencoded' : 'application/json',
      ...(init.basic ? { Authorization: `Basic ${Buffer.from(init.basic).toString('base64')}` } : {}),
    },
    body: init.form ? new URLSearchParams(body).toString() : JSON.stringify(body),
  })
  return { status: response.status, headers: response.headers, body: (await response.json()) as Record<string, unknown> }
}

beforeEach(() => {
  clients.clear()
  codes.clear()
  store.issued.length = 0
  store.audits.length = 0
  register('spa', 'public', null)
  register('portal', 'confidential', `hash:${secret}`)
})

describe('public client', () => {
  it('cannot start a flow without an S256 PKCE challenge', async () => {
    const request = { clientId: 'spa', redirectUri, responseType: 'code' }
    await expect(validateAuthorizeRequest(request)).rejects.toMatchObject({ code: 'INVALID_REQUEST' })
    await expect(createAuthorizationCode('fake-user', request)).rejects.toMatchObject({ code: 'INVALID_REQUEST' })
    await expect(
      createAuthorizationCode('fake-user', { ...request, codeChallenge: challenge }),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' })
    expect(codes.size).toBe(0)
  })

  it('exchanges its code with the matching verifier and no secret', async () => {
    const code = await authorize('spa', true)
    const reply = await exchange({ client_id: 'spa', code, code_verifier: verifier }, { form: true })
    expect(reply.status).toBe(200)
    expect(reply.body).toMatchObject({ access_token: 'fake-access', token_type: 'Bearer', id_token: 'fake-id-token' })
    expect(store.issued).toEqual(['spa'])
  })

  it('refuses a stolen code presented without the verifier or with another one', async () => {
    const code = await authorize('spa', true)
    const missing = await exchange({ client_id: 'spa', code })
    expect(missing).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    const wrong = await exchange({ client_id: 'spa', code, code_verifier: 'x'.repeat(43) })
    expect(wrong).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    expect(store.issued).toEqual([])
    // The refusals did not consume the code: its owner can still redeem it.
    expect((await exchange({ client_id: 'spa', code, code_verifier: verifier })).status).toBe(200)
  })

  it('refuses a code that carries no challenge, however it came to exist', async () => {
    codes.set('legacy-code', {
      id: 'legacy', code: 'legacy-code', clientId: 'spa', userId: 'fake-user', redirectUri, scope: null,
      codeChallenge: null, state: null, nonce: null, browserSessionId: null,
      expiresAt: new Date(Date.now() + 60_000), usedAt: null,
    })
    const reply = await exchange({ client_id: 'spa', code: 'legacy-code' })
    expect(reply).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    expect(store.issued).toEqual([])
  })

  it('cannot present a secret', async () => {
    const code = await authorize('spa', true)
    const reply = await exchange({ client_id: 'spa', code, code_verifier: verifier, client_secret: secret })
    expect(reply).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
  })
})

describe('confidential client', () => {
  it('exchanges a code with its secret in the body or in Basic auth', async () => {
    const first = await exchange({ client_id: 'portal', code: await authorize('portal', false), client_secret: secret })
    expect(first.status).toBe(200)
    const second = await exchange({ client_id: 'portal', code: await authorize('portal', false) }, { form: true, basic: `portal:${secret}` })
    expect(second.status).toBe(200)
    expect(store.issued).toEqual(['portal', 'portal'])
  })

  it('refuses a stolen code presented without the secret, with or without PKCE', async () => {
    const plain = await authorize('portal', false)
    const reply = await exchange({ client_id: 'portal', code: plain })
    expect(reply).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
    // PKCE does not replace client authentication for a confidential client.
    const pkce = await authorize('portal', true)
    const withVerifier = await exchange({ client_id: 'portal', code: pkce, code_verifier: verifier })
    expect(withVerifier).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
    expect(store.issued).toEqual([])
    // Neither refusal consumed a code.
    expect((await exchange({ client_id: 'portal', code: plain, client_secret: secret })).status).toBe(200)
  })

  it('refuses a wrong secret and names the Basic challenge', async () => {
    const code = await authorize('portal', false)
    const body = await exchange({ client_id: 'portal', code, client_secret: `${secret}-wrong` })
    expect(body).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
    const basic = await exchange({ client_id: 'portal', code }, { basic: `portal:${secret}-wrong` })
    expect(basic.status).toBe(401)
    expect(basic.headers.get('www-authenticate')).toContain('Basic')
    expect(store.issued).toEqual([])
  })

  it('must also present the verifier when it used PKCE', async () => {
    const code = await authorize('portal', true)
    const missing = await exchange({ client_id: 'portal', code, client_secret: secret })
    expect(missing).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    const wrong = await exchange({ client_id: 'portal', code, client_secret: secret, code_verifier: 'y'.repeat(43) })
    expect(wrong).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    expect(store.issued).toEqual([])
    const reply = await exchange({ client_id: 'portal', code, client_secret: secret, code_verifier: verifier })
    expect(reply.status).toBe(200)
  })

  it('cannot exchange anything while it has no secret', async () => {
    register('unprovisioned', 'confidential', null)
    const code = await authorize('unprovisioned', false)
    expect(await exchange({ client_id: 'unprovisioned', code })).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
    expect(await exchange({ client_id: 'unprovisioned', code, client_secret: secret })).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
    expect(store.issued).toEqual([])
  })
})

describe('any client', () => {
  it('cannot redeem a code issued to another client', async () => {
    register('other', 'confidential', `hash:${secret}-other`)
    const code = await authorize('portal', false)
    const reply = await exchange({ client_id: 'other', code, client_secret: `${secret}-other` })
    expect(reply).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    const publicCode = await authorize('spa', true)
    const crossed = await exchange({ client_id: 'portal', code: publicCode, client_secret: secret, code_verifier: verifier })
    expect(crossed).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    expect(store.issued).toEqual([])
  })

  it('is refused when unknown or inactive', async () => {
    const code = await authorize('spa', true)
    expect(await exchange({ client_id: 'missing', code, code_verifier: verifier })).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
    clients.get('spa')!.active = false
    expect(await exchange({ client_id: 'spa', code, code_verifier: verifier })).toMatchObject({ status: 401, body: { error: 'invalid_client' } })
  })

  it('redeems a code once; a second use is refused and audited', async () => {
    const code = await authorize('spa', true)
    expect((await exchange({ client_id: 'spa', code, code_verifier: verifier })).status).toBe(200)
    const replay = await exchange({ client_id: 'spa', code, code_verifier: verifier })
    expect(replay).toMatchObject({ status: 400, body: { error: 'invalid_grant' } })
    expect(store.audits).toContain('oauth.code_reuse')
    expect(store.issued).toEqual(['spa'])
  })
})
