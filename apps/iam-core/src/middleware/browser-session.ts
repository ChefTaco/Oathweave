import type { Context, MiddlewareHandler } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { SignJWT, jwtVerify, createLocalJWKSet } from 'jose'
import { createHash } from 'node:crypto'
import { env } from '../config/env.js'
import { prisma } from '../db/client.js'
import {
  getPrivateKey,
  getPublishedSigningJwks,
  getSigningKeyId,
} from '../utils/keys.js'
import { verifyAccessToken } from '../services/token-service.js'
import { authMiddleware } from './auth.js'
import { ApiError, type Principal } from '../types/index.js'

const COOKIE = '__Host-oathweave_sso'
const AUDIENCE = 'oathweave-browser-session'

export function requireBrowserOrigin(c: Context): void {
  const origin = c.req.header('origin')
  if (
    !origin ||
    !env.CORS_ORIGIN.split(',')
      .map((value) => value.trim())
      .includes(origin)
  )
    throw new ApiError(403, 'INVALID_ORIGIN', 'Browser origin is not allowed')
}

/** Opt-in browser responses keep long-lived credentials out of JavaScript. */
export const establishBrowserSession: MiddlewareHandler = async (c, next) => {
  const browser = c.req.header('x-oathweave-browser') === 'true'
  if (browser) requireBrowserOrigin(c)
  await next()
  if (!browser || !c.res.ok || c.req.method !== 'POST') return
  const raw: unknown = await c.res
    .clone()
    .json()
    .catch(() => ({}))
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return
  const body = raw as Record<string, unknown>
  if (
    typeof body.accessToken !== 'string' ||
    typeof body.refreshToken !== 'string'
  )
    return
  const token = await verifyAccessToken(body.accessToken)
  if (token.actorType !== 'USER' || !token.sessionId || token.clientId)
    throw new ApiError(401, 'INVALID_SESSION', 'Interactive identity required')
  const now = Math.floor(Date.now() / 1000)
  const signed = await new SignJWT({
    purpose: 'browser_sso',
    sessionId: token.sessionId,
    auth_time: now,
  })
    .setProtectedHeader({ alg: 'RS256', kid: await getSigningKeyId() })
    .setSubject(token.sub)
    .setIssuer(env.JWT_ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + env.JWT_REFRESH_TTL)
    .sign(await getPrivateKey())
  await prisma.refreshToken.deleteMany({
    where: {
      tokenHash: createHash('sha256').update(body.refreshToken).digest('hex'),
    },
  })
  delete body.refreshToken
  c.res.headers.delete('set-cookie')
  c.res = new Response(JSON.stringify(body), {
    status: c.res.status,
    headers: c.res.headers,
  })
  c.header('Cache-Control', 'no-store')
  setCookie(c, COOKIE, signed, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/',
    maxAge: env.JWT_REFRESH_TTL,
  })
}

export async function browserPrincipal(c: Context): Promise<Principal | null> {
  const cookie = getCookie(c, COOKIE)
  if (!cookie) return null
  try {
    const { payload } = await jwtVerify(
      cookie,
      createLocalJWKSet(await getPublishedSigningJwks()),
      {
        algorithms: ['RS256'],
        issuer: env.JWT_ISSUER,
        audience: AUDIENCE,
        requiredClaims: ['sub', 'iat', 'exp'],
      },
    )
    if (
      payload.purpose !== 'browser_sso' ||
      typeof payload.sessionId !== 'string'
    )
      return null
    const session = await prisma.session.findFirst({
      where: {
        id: payload.sessionId,
        userId: payload.sub,
        revokedAt: null,
        expiresAt: { gt: new Date() },
        user: { active: true },
      },
      include: { user: { include: { roles: { include: { role: true } } } } },
    })
    if (!session) return null
    return {
      sub: session.userId,
      actorType: 'USER',
      email: session.user.email,
      username: session.user.username,
      roles: session.user.roles.map((value) => value.role.name),
      permissions: session.user.roles.flatMap(
        (value) => JSON.parse(value.role.permissions) as string[],
      ),
      sessionId: session.id,
      clientId: undefined,
    }
  } catch {
    return null
  }
}

export const browserAuthorization: MiddlewareHandler = async (c, next) => {
  if (c.req.header('authorization')) return authMiddleware(c, next)
  if (c.req.method !== 'GET') requireBrowserOrigin(c)
  const principal = await browserPrincipal(c)
  if (!principal) return c.json({ error: 'LOGIN_REQUIRED' }, 401)
  c.set('principal', principal)
  return next()
}

export async function clearBrowserSession(c: Context): Promise<void> {
  requireBrowserOrigin(c)
  const principal = await browserPrincipal(c)
  if (principal?.sessionId)
    await prisma.session.updateMany({
      where: { id: principal.sessionId, userId: principal.sub },
      data: { revokedAt: new Date() },
    })
  deleteCookie(c, COOKIE, {
    secure: true,
    httpOnly: true,
    sameSite: 'Strict',
    path: '/',
  })
}
