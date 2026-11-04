/**
 * WebAuthn/FIDO2 MFA routes.
 *
 * Registration: GET /options → POST /register
 * Authentication: GET /authenticate-options → POST /authenticate
 *
 * All routes require a valid Bearer JWT (except /authenticate which
 * accepts an mfaToken for the login-time challenge flow).
 */

import { Hono } from 'hono'
import {
  PasskeyRegisterSchema as RegisterBodySchema,
  PasskeyAuthenticationSchema as AuthenticationBodySchema,
  PasskeyAuthenticationOptionsSchema,
} from '../schemas/webauthn.js'
import { nanoid } from 'nanoid'
import { setCookie } from 'hono/cookie'
import { ApiError, type Principal } from '../types/index.js'
import { prisma } from '../db/client.js'
import { authMiddleware } from '../middleware/auth.js'
import { rateLimitMiddleware } from '../middleware/rate-limit.js'
import { env } from '../config/env.js'
import { getClientIp } from '../utils/ip.js'
import { credentialLookupIds } from '../services/webauthn-credentials.js'
import {
  loginChallengeUser,
  consumeLoginChallenge,
} from '../services/login-challenge.js'
import { requireRecentSession } from '../middleware/recent-session.js'
import { createSession } from '../services/session-service.js'
import { issueTokenPair } from '../services/token-service.js'
import { logAuditEvent } from '../services/audit-service.js'
import {
  getRegistrationOptions,
  verifyRegistration,
  getAuthenticationOptions,
  verifyAuthentication,
} from '../services/webauthn-service.js'

export const webauthnRouter = new Hono()

const userIdFromMfaToken = loginChallengeUser

// ── Registration ──

/** Get registration options (challenge). */
webauthnRouter.get(
  '/options',
  authMiddleware,
  requireRecentSession,
  async (c) => {
    const principal = c.get('principal') as unknown as Principal | undefined
    if (!principal)
      throw new ApiError(401, 'UNAUTHORIZED', 'Authentication required')

    const user = await prisma.user.findUnique({
      where: { id: principal.sub },
      select: { id: true, email: true, username: true },
    })
    if (!user) throw new ApiError(404, 'NOT_FOUND', 'User not found')

    const existing = await prisma.webAuthnCredential.findMany({
      where: { userId: user.id },
      select: {
        credentialId: true,
        publicKey: true,
        counter: true,
        transports: true,
      },
    })

    const creds = existing.map((c) => ({
      credentialId: c.credentialId,
      publicKey: c.publicKey,
      counter: c.counter,
      transports: JSON.parse(c.transports) as string[],
    }))

    const options = await getRegistrationOptions(
      user.id,
      user.email,
      user.username,
      creds,
      principal.sessionId ?? principal.sub,
    )
    return c.json({ success: true, data: options })
  },
)

/** Complete registration (verify attestation). */
webauthnRouter.post(
  '/register',
  authMiddleware,
  requireRecentSession,
  async (c) => {
    const principal = c.get('principal') as unknown as Principal | undefined
    if (!principal)
      throw new ApiError(401, 'UNAUTHORIZED', 'Authentication required')

    const body = RegisterBodySchema.parse(await c.req.json())

    const verification = await verifyRegistration(
      principal.sub,
      body.response,
      principal.sessionId ?? principal.sub,
    )
    if (!verification.verified || !verification.registrationInfo) {
      throw new ApiError(
        400,
        'VALIDATION_ERROR',
        'WebAuthn registration verification failed',
      )
    }

    const { credential, credentialDeviceType, credentialBackedUp } =
      verification.registrationInfo
    if (
      await prisma.webAuthnCredential.findFirst({
        where: { credentialId: { in: credentialLookupIds(credential.id) } },
      })
    ) {
      throw new ApiError(409, 'CONFLICT', 'This passkey is already registered')
    }
    await prisma.webAuthnCredential.create({
      data: {
        id: nanoid(),
        userId: principal.sub,
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: JSON.stringify(credential.transports ?? []),
        friendlyName: body.friendlyName,
      },
    })

    // Enable MFA on the user if not already
    await prisma.user.update({
      where: { id: principal.sub },
      data: { mfaEnabled: true },
    })

    return c.json({ success: true, message: 'WebAuthn credential registered' })
  },
)

// ── Authentication ──

/** Get authentication options (challenge). */
const authenticationOptions: import('hono').Handler = async (c) => {
  const mfaToken =
    c.req.method === 'POST'
      ? PasskeyAuthenticationOptionsSchema.parse(await c.req.json()).mfaToken
      : c.req.query('mfaToken')
  if (!mfaToken)
    throw new ApiError(400, 'VALIDATION_ERROR', 'mfaToken required')
  const userId = await userIdFromMfaToken(mfaToken)

  const existing = await prisma.webAuthnCredential.findMany({
    where: { userId },
    select: {
      credentialId: true,
      publicKey: true,
      counter: true,
      transports: true,
    },
  })

  if (existing.length === 0) {
    throw new ApiError(
      404,
      'NOT_FOUND',
      'No WebAuthn credentials found for this user',
    )
  }

  const creds = existing.map((c) => ({
    credentialId: c.credentialId,
    publicKey: c.publicKey,
    counter: c.counter,
    transports: JSON.parse(c.transports) as string[],
  }))

  const options = await getAuthenticationOptions(userId, creds, mfaToken)
  return c.json({ success: true, data: options })
}
// Keep native GET compatibility; browser challenges stay out of URL/history logs.
webauthnRouter.get(
  '/authenticate-options',
  rateLimitMiddleware({
    keyPrefix: 'rl:webauthn-options',
    max: 10,
    windowMs: 300_000,
  }),
  authenticationOptions,
)
webauthnRouter.post(
  '/authenticate-options',
  rateLimitMiddleware({
    keyPrefix: 'rl:webauthn-options',
    max: 10,
    windowMs: 300_000,
  }),
  authenticationOptions,
)

/** Verify authentication assertion. */
webauthnRouter.post(
  '/authenticate',
  rateLimitMiddleware({
    keyPrefix: 'rl:webauthn-auth',
    max: 5,
    windowMs: 300_000,
  }),
  async (c) => {
    const body = AuthenticationBodySchema.parse(await c.req.json())
    const userId = await userIdFromMfaToken(body.mfaToken)

    const challengeUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { active: true, mfaEnabled: true, lockedUntil: true },
    })
    if (
      !challengeUser?.active ||
      !challengeUser.mfaEnabled ||
      (challengeUser.lockedUntil && challengeUser.lockedUntil > new Date())
    ) {
      throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid credentials')
    }

    const credentialIdFromResponse = (body.response as { id?: string }).id
    if (
      typeof credentialIdFromResponse !== 'string' ||
      !/^[A-Za-z0-9_-]{1,2048}$/.test(credentialIdFromResponse)
    ) {
      throw new ApiError(
        400,
        'VALIDATION_ERROR',
        'Missing credential ID in response',
      )
    }

    const stored = await prisma.webAuthnCredential.findFirst({
      where: {
        credentialId: { in: credentialLookupIds(credentialIdFromResponse) },
        userId,
      },
    })

    if (!stored || stored.userId !== userId) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Unknown credential')
    }

    const credential = {
      credentialId: credentialIdFromResponse,
      publicKey: stored.publicKey,
      counter: stored.counter,
      transports: JSON.parse(stored.transports) as string[],
    }

    const verification = await verifyAuthentication(
      userId,
      body.response,
      credential,
      body.mfaToken,
    )
    if (!verification.verified) {
      throw new ApiError(
        400,
        'VALIDATION_ERROR',
        'WebAuthn authentication failed',
      )
    }

    // Update counter for clone detection
    const advanced = await prisma.webAuthnCredential.updateMany({
      where: { id: stored.id, counter: stored.counter },
      data: {
        counter: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      },
    })
    if (advanced.count !== 1)
      throw new ApiError(
        400,
        'INVALID_CREDENTIALS',
        'Passkey changed during verification; try again',
      )
    await consumeLoginChallenge(body.mfaToken)

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { roles: { include: { role: true } } },
    })
    if (!user || !user.active || !user.mfaEnabled)
      throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid credentials')
    const roles = user.roles.map((assignment) => assignment.role.name)
    const permissions = [
      ...new Set(
        user.roles.flatMap((assignment) => {
          const value = assignment.role.permissions
          return (
            typeof value === 'string' ? JSON.parse(value) : value
          ) as string[]
        }),
      ),
    ]
    const ip = getClientIp(c)
    const userAgent = c.req.header('user-agent')
    const { sessionId, riskScore, riskFactors } = await createSession(
      userId,
      ip,
      userAgent,
    )
    const tokenPair = await issueTokenPair(
      userId,
      user.email,
      user.username,
      roles,
      permissions,
      sessionId,
      ip,
      undefined,
      userAgent,
    )
    await prisma.user.update({
      where: { id: userId },
      data: {
        failedAttempts: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
        lastLoginIp: ip,
      },
    })
    setCookie(c, 'iam_refresh', tokenPair.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: env.JWT_REFRESH_TTL,
      path: '/api/v1/auth',
    })
    await logAuditEvent({
      eventType: 'auth.webauthn_challenge',
      category: 'AUTHENTICATION',
      actorId: userId,
      actorType: 'USER',
      actorEmail: user.email,
      ipAddress: ip,
      userAgent,
      action: 'webauthn_challenge',
      outcome: 'SUCCESS',
      source: 'iam-api',
    })
    return c.json({
      success: true,
      verified: true,
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      expiresIn: tokenPair.expiresIn,
      sessionId,
      riskScore,
      riskFactors,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.displayName,
        roles,
        permissions,
      },
    })
  },
)

// ── Management ──

/** List user's registered WebAuthn credentials. */
webauthnRouter.get('/credentials', authMiddleware, async (c) => {
  const principal = c.get('principal') as unknown as Principal | undefined
  if (!principal)
    throw new ApiError(401, 'UNAUTHORIZED', 'Authentication required')

  const credentials = await prisma.webAuthnCredential.findMany({
    where: { userId: principal.sub },
    select: {
      id: true,
      credentialId: true,
      deviceType: true,
      backedUp: true,
      friendlyName: true,
      lastUsedAt: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  })

  return c.json({ success: true, data: credentials })
})

/** Delete a WebAuthn credential. */
webauthnRouter.delete(
  '/credentials/:id',
  authMiddleware,
  requireRecentSession,
  async (c) => {
    const principal = c.get('principal') as unknown as Principal | undefined
    if (!principal)
      throw new ApiError(401, 'UNAUTHORIZED', 'Authentication required')

    const credential = await prisma.webAuthnCredential.findUnique({
      where: { id: c.req.param('id') },
    })

    if (!credential || credential.userId !== principal.sub) {
      throw new ApiError(404, 'NOT_FOUND', 'Credential not found')
    }

    await prisma.webAuthnCredential.delete({ where: { id: credential.id } })

    // Check if user still has any MFA methods
    const remaining = await prisma.webAuthnCredential.count({
      where: { userId: principal.sub },
    })
    const user = await prisma.user.findUnique({
      where: { id: principal.sub },
      select: { mfaSecret: true, mfaVerifiedAt: true },
    })

    if (remaining === 0 && !(user?.mfaSecret && user.mfaVerifiedAt)) {
      await prisma.user.update({
        where: { id: principal.sub },
        data: {
          mfaEnabled: false,
          mfaSecret: null,
          mfaVerifiedAt: null,
          mfaBackupCodes: null,
        },
      })
    }

    return c.json({ success: true, message: 'Credential deleted' })
  },
)
