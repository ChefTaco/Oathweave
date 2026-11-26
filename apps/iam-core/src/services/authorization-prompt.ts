/**
 * authorization-prompt.ts — OpenID Connect `prompt` and `max_age` for the authorization endpoint.
 *
 * `prompt=login` (and `select_account`) issues a code only for a sign-in completed after the
 * request first reached Oathweave. The first attempt answers LOGIN_REQUIRED with a short-lived
 * signed login ticket bound to this exact request; after a fresh interactive sign-in the caller
 * repeats the request with the ticket. A session authenticated before the ticket never satisfies
 * it, so a live SSO cookie alone cannot skip the sign-in.
 *
 * `max_age=N` reuses the session only when its authentication time is at most N seconds old;
 * otherwise it asks for a sign-in the same way. `max_age=0` is `prompt=login`. A sign-in completed
 * for this request (after its ticket) satisfies any `max_age`.
 *
 * `prompt=none` never shows an interaction: when one would be needed the caller receives an
 * OAuth error (`login_required` or `consent_required`) to return to the client's callback.
 *
 * The authentication time is the session's last interactive authentication: its step-up
 * verification time when it has one, otherwise its creation (the sign-in). It is also the
 * ID token's `auth_time`.
 */
import { createHash } from 'node:crypto'
import { SignJWT, jwtVerify, createLocalJWKSet } from 'jose'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { ApiError, type Principal } from '../types/index.js'
import { getPrivateKey, getPublishedSigningJwks, getSigningKeyId } from '../utils/keys.js'
import { issuerForClient } from './browser-policies.js'

export const PROMPT_VALUES = ['none', 'login', 'consent', 'select_account'] as const
export type PromptValue = (typeof PROMPT_VALUES)[number]

/** How long a login ticket stays usable: the authorization code lifetime. */
export const LOGIN_TICKET_TTL_SECONDS = 600
const TICKET_AUDIENCE = 'oathweave-authorize-login'

/** The request a login ticket is bound to. */
export interface AuthorizationBinding {
  clientId: string
  redirectUri: string
  state?: string | undefined
  nonce?: string | undefined
  codeChallenge?: string | undefined
}

export interface PromptParams {
  prompt?: string | undefined
  maxAge?: number | undefined
  loginTicket?: string | undefined
}

export type LoginReason = 'no_session' | 'prompt_login' | 'max_age'

export type PromptOutcome =
  | { ok: true; prompts: ReadonlySet<PromptValue>; authenticatedForRequest: boolean }
  | { ok: false; prompts: ReadonlySet<PromptValue>; reason: LoginReason }

/** Parse a space-delimited `prompt`. `none` cannot be combined with any other value. */
export function parsePrompt(raw: string | undefined): ReadonlySet<PromptValue> {
  if (raw === undefined || raw.trim() === '') return new Set()
  const values = raw.split(' ').filter(Boolean)
  const known = new Set<string>(PROMPT_VALUES)
  if (values.some((value) => !known.has(value)))
    throw new ApiError(400, 'INVALID_REQUEST', `prompt supports only ${PROMPT_VALUES.join(', ')}`)
  const prompts = new Set(values as PromptValue[])
  if (prompts.has('none') && prompts.size > 1)
    throw new ApiError(400, 'INVALID_REQUEST', 'prompt=none cannot be combined with other values')
  return prompts
}

/** A session's last interactive authentication: step-up verification, otherwise sign-in. */
export function sessionAuthTime(session: { createdAt: Date; stepUpVerifiedAt: Date | null }): Date {
  return session.stepUpVerifiedAt ?? session.createdAt
}

function bindingHash(binding: AuthorizationBinding): string {
  return createHash('sha256')
    .update(JSON.stringify([binding.clientId, binding.redirectUri, binding.state ?? null, binding.nonce ?? null, binding.codeChallenge ?? null]))
    .digest('base64url')
}

/** A signed ticket recording when this exact authorization request asked for a sign-in. */
export async function issueLoginTicket(binding: AuthorizationBinding, now = Date.now()): Promise<string> {
  const seconds = Math.floor(now / 1000)
  return new SignJWT({ purpose: 'authorize_login', bnd: bindingHash(binding), rat: now })
    .setProtectedHeader({ alg: 'RS256', kid: await getSigningKeyId() })
    .setIssuer(env.JWT_ISSUER)
    .setAudience(TICKET_AUDIENCE)
    .setIssuedAt(seconds)
    .setExpirationTime(seconds + LOGIN_TICKET_TTL_SECONDS)
    .sign(await getPrivateKey())
}

/** The time (ms) a valid ticket for this request asked for a sign-in, or null. */
export async function verifyLoginTicket(ticket: string | undefined, binding: AuthorizationBinding): Promise<number | null> {
  if (!ticket) return null
  try {
    const { payload } = await jwtVerify(ticket, createLocalJWKSet(await getPublishedSigningJwks()), {
      algorithms: ['RS256'],
      issuer: env.JWT_ISSUER,
      audience: TICKET_AUDIENCE,
      requiredClaims: ['iat', 'exp'],
    })
    if (payload.purpose !== 'authorize_login' || payload.bnd !== bindingHash(binding) || typeof payload.rat !== 'number') return null
    return payload.rat
  } catch {
    return null
  }
}

/** Decide whether the principal's session satisfies `prompt` and `max_age` for this request. */
export async function evaluatePrompt(
  principal: Principal | undefined,
  params: PromptParams,
  binding: AuthorizationBinding,
): Promise<PromptOutcome> {
  const prompts = parsePrompt(params.prompt)
  // max_age=0 asks for a sign-in on every request (OpenID Connect Core §3.1.2.1).
  const forceLogin = prompts.has('login') || prompts.has('select_account') || params.maxAge === 0
  if (!principal) return { ok: false, prompts, reason: 'no_session' }
  if (!forceLogin && params.maxAge === undefined) return { ok: true, prompts, authenticatedForRequest: false }

  const session = principal.sessionId && principal.actorType === 'USER'
    ? await prisma.session.findFirst({
        where: { id: principal.sessionId, userId: principal.sub, revokedAt: null, expiresAt: { gt: new Date() } },
        select: { createdAt: true, stepUpVerifiedAt: true },
      })
    : null
  // Without an interactive session there is no authentication time to judge.
  if (!session) return { ok: false, prompts, reason: params.maxAge !== undefined ? 'max_age' : 'prompt_login' }
  const authTime = sessionAuthTime(session).getTime()
  const requestedAt = await verifyLoginTicket(params.loginTicket, binding)
  const authenticatedForRequest = requestedAt !== null && authTime >= requestedAt
  if (forceLogin && !authenticatedForRequest)
    return { ok: false, prompts, reason: prompts.has('login') || prompts.has('select_account') ? 'prompt_login' : 'max_age' }
  if (params.maxAge !== undefined && !authenticatedForRequest && Math.floor((Date.now() - authTime) / 1000) > params.maxAge)
    return { ok: false, prompts, reason: 'max_age' }
  return { ok: true, prompts, authenticatedForRequest }
}

const LOGIN_MESSAGES: Record<LoginReason, string> = {
  no_session: 'Sign in to continue',
  prompt_login: 'The application asked you to sign in again',
  max_age: 'Your sign-in is too old for this application; sign in again',
}

/** The LOGIN_REQUIRED body: sign in, then repeat the request with `loginTicket`. */
export async function loginRequiredBody(reason: LoginReason, binding: AuthorizationBinding) {
  return {
    error: 'LOGIN_REQUIRED' as const,
    message: LOGIN_MESSAGES[reason],
    reason,
    loginTicket: await issueLoginTicket(binding),
    loginTicketExpiresIn: LOGIN_TICKET_TTL_SECONDS,
  }
}

export type AuthorizationErrorCode = 'access_denied' | 'login_required' | 'consent_required'

/**
 * An OAuth error response (RFC 6749 §4.1.2.1, RFC 9207 `iss`) for a request whose client and
 * redirect URI were already validated: the error, the request's state and the issuer, and
 * `redirectTo`, the client's callback carrying them.
 */
export function authorizationErrorResponse(
  binding: AuthorizationBinding,
  error: AuthorizationErrorCode,
  description: string,
) {
  const iss = issuerForClient(binding.clientId, env.JWT_ISSUER)
  const url = new URL(binding.redirectUri)
  url.searchParams.set('error', error)
  url.searchParams.set('error_description', description)
  if (binding.state !== undefined) url.searchParams.set('state', binding.state)
  url.searchParams.set('iss', iss)
  return {
    error,
    error_description: description,
    ...(binding.state !== undefined ? { state: binding.state } : {}),
    iss,
    redirectTo: url.toString(),
  }
}
