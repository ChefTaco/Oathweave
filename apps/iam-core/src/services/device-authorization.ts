/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628): a CLI or headless agent signs a person in
 * without ever seeing their password. The device asks for a code pair, shows the person the
 * short user code, and polls the token endpoint while the person approves it in a browser.
 *
 * The device code is a 256-bit secret stored only as its SHA-256 digest; the user code is short
 * enough to type (8 letters, about 34 bits), so entering it is rate-limited and needs a signed-in
 * person, and it lives for ten minutes.
 */
import { randomBytes, randomInt } from 'node:crypto'
import { sha256Hex } from '@hivemagnus/hive-common/secrets'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { ApiError } from '../types/index.js'
import { logAuditEvent } from './audit-service.js'
import { createSession } from './session-service.js'
import { issueTokenPair } from './token-service.js'
import { parsePermissionList, userTokenGrants } from './effective-grants.js'

export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
export const DEVICE_CODE_TTL_SECONDS = 600
export const DEVICE_POLL_INTERVAL_SECONDS = 5
/** RFC 8628 §6.1: no vowels or look-alikes, so codes are easy to read and form no words. */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ'
const USER_CODE_LENGTH = 8

function newUserCode(): string {
  let code = ''
  for (let index = 0; index < USER_CODE_LENGTH; index++) code += USER_CODE_ALPHABET[randomInt(USER_CODE_ALPHABET.length)]
  return code
}

/** What a person typed, as stored: letters only, upper case (`bcdf-ghjk` is `BCDFGHJK`). */
export function normalizeUserCode(input: string): string {
  return input.toUpperCase().replace(/[^A-Z]/g, '')
}

export function formatUserCode(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4)}`
}

export function clientAllowsDeviceGrant(grantTypes: unknown): boolean {
  return parsePermissionList(grantTypes).includes(DEVICE_CODE_GRANT)
}

export interface DeviceAuthorizationResponse {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string
  expires_in: number
  interval: number
}

/** RFC 8628 §3.1–3.2. The caller has authenticated (or identified) the client. */
export async function startDeviceAuthorization(clientId: string, scope: string | undefined, ipAddress: string): Promise<DeviceAuthorizationResponse> {
  const verification = env.IAM_DEVICE_VERIFICATION_URL
  if (!verification)
    throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', 'Set IAM_DEVICE_VERIFICATION_URL to the page where people approve device sign-ins')
  const client = await prisma.client.findUnique({ where: { id: clientId }, select: { active: true, grantTypes: true } })
  if (!client?.active) throw new ApiError(401, 'INVALID_CLIENT', 'Unknown or inactive client')
  if (!clientAllowsDeviceGrant(client.grantTypes))
    throw new ApiError(400, 'UNAUTHORIZED_CLIENT', 'Client is not authorized for the device authorization grant')

  const deviceCode = randomBytes(32).toString('base64url')
  let userCode = newUserCode()
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      await prisma.deviceAuthorization.create({
        data: {
          deviceCodeHash: sha256Hex(deviceCode),
          userCode,
          clientId,
          scope: scope ?? null,
          interval: DEVICE_POLL_INTERVAL_SECONDS,
          expiresAt: new Date(Date.now() + DEVICE_CODE_TTL_SECONDS * 1000),
        },
      })
      break
    } catch (error) {
      // A user code collided with a live one: draw another.
      if (attempt === 4) throw error
      userCode = newUserCode()
    }
  }
  await logAuditEvent({
    eventType: 'oauth.device_authorization',
    category: 'AUTHENTICATION',
    actorId: clientId,
    actorType: 'SERVICE_ACCOUNT',
    clientId,
    ipAddress,
    action: 'device_authorization',
    outcome: 'SUCCESS',
    detail: { scope },
    source: 'iam-api',
  })
  const complete = new URL(verification)
  complete.searchParams.set('user_code', formatUserCode(userCode))
  return {
    device_code: deviceCode,
    user_code: formatUserCode(userCode),
    verification_uri: verification,
    verification_uri_complete: complete.toString(),
    expires_in: DEVICE_CODE_TTL_SECONDS,
    interval: DEVICE_POLL_INTERVAL_SECONDS,
  }
}

async function pendingByUserCode(input: string) {
  const userCode = normalizeUserCode(input)
  if (userCode.length !== USER_CODE_LENGTH) return null
  return prisma.deviceAuthorization.findFirst({ where: { userCode, status: 'pending', expiresAt: { gt: new Date() } } })
}

/** What the approval page shows: which client asks, for which scope. */
export async function describeDeviceAuthorization(input: string) {
  const pending = await pendingByUserCode(input)
  if (!pending) throw new ApiError(404, 'NOT_FOUND', 'Unknown or expired code')
  const client = await prisma.client.findUnique({ where: { id: pending.clientId }, select: { name: true, description: true } })
  return {
    userCode: formatUserCode(pending.userCode),
    clientId: pending.clientId,
    clientName: client?.name ?? pending.clientId,
    clientDescription: client?.description ?? null,
    scope: pending.scope,
    expiresAt: pending.expiresAt.toISOString(),
  }
}

/** A signed-in person approves or denies the device sign-in shown with this user code. */
export async function decideDeviceAuthorization(
  input: string,
  person: { userId: string; sessionId: string },
  decision: 'approve' | 'deny',
  ipAddress: string,
): Promise<void> {
  const pending = await pendingByUserCode(input)
  if (!pending) throw new ApiError(404, 'NOT_FOUND', 'Unknown or expired code')
  const session = await prisma.session.findFirst({
    where: { id: person.sessionId, userId: person.userId, revokedAt: null, expiresAt: { gt: new Date() } },
    select: { createdAt: true, stepUpVerifiedAt: true },
  })
  if (!session) throw new ApiError(401, 'UNAUTHORIZED', 'Interactive session required')
  const decided = await prisma.deviceAuthorization.updateMany({
    where: { id: pending.id, status: 'pending', expiresAt: { gt: new Date() } },
    data: {
      status: decision === 'approve' ? 'approved' : 'denied',
      userId: person.userId,
      authTime: session.stepUpVerifiedAt ?? session.createdAt,
    },
  })
  if (decided.count !== 1) throw new ApiError(404, 'NOT_FOUND', 'Unknown or expired code')
  await logAuditEvent({
    eventType: decision === 'approve' ? 'oauth.device_approved' : 'oauth.device_denied',
    category: 'AUTHENTICATION',
    actorId: person.userId,
    actorType: 'USER',
    clientId: pending.clientId,
    ipAddress,
    action: decision === 'approve' ? 'device_approve' : 'device_deny',
    outcome: 'SUCCESS',
    detail: { clientId: pending.clientId, scope: pending.scope },
    source: 'iam-api',
  })
}

export interface DeviceTokenResult {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  scope?: string
  userId: string
  email: string
  username: string
  displayName: string
  sessionId: string
  authTime?: Date
}

/** RFC 8628 §3.4–3.5: one poll of the token endpoint. */
export async function exchangeDeviceCode(
  deviceCode: string,
  client: { clientId: string; clientType: string; authenticated: boolean },
  ipAddress: string,
  userAgent?: string,
): Promise<DeviceTokenResult> {
  const row = await prisma.deviceAuthorization.findUnique({ where: { deviceCodeHash: sha256Hex(deviceCode) } })
  // Another client's device code answers exactly like an unknown one.
  if (!row || row.clientId !== client.clientId) throw new ApiError(400, 'INVALID_GRANT', 'Device code is invalid')
  if (client.clientType !== 'public' && !client.authenticated)
    throw new ApiError(401, 'INVALID_CLIENT', 'Client authentication required: this confidential client must send its client secret')
  const now = new Date()
  if (row.expiresAt <= now) throw new ApiError(400, 'EXPIRED_TOKEN', 'Device code has expired; start again')
  if (row.status === 'denied') throw new ApiError(400, 'ACCESS_DENIED', 'The sign-in was declined')
  if (row.status === 'consumed') throw new ApiError(400, 'INVALID_GRANT', 'Device code has already been used')
  if (row.status === 'pending') {
    // §3.5: a client that polls faster than the interval is told to slow down, by 5 seconds more.
    if (row.lastPolledAt && now.getTime() - row.lastPolledAt.getTime() < row.interval * 1000) {
      await prisma.deviceAuthorization.update({ where: { id: row.id }, data: { lastPolledAt: now, interval: row.interval + 5 } })
      throw new ApiError(400, 'SLOW_DOWN', `Poll at most every ${row.interval + 5} seconds`)
    }
    await prisma.deviceAuthorization.update({ where: { id: row.id }, data: { lastPolledAt: now } })
    throw new ApiError(400, 'AUTHORIZATION_PENDING', 'The person has not approved the sign-in yet')
  }

  const consumed = await prisma.deviceAuthorization.updateMany({
    where: { id: row.id, status: 'approved', expiresAt: { gt: now } },
    data: { status: 'consumed' },
  })
  if (consumed.count !== 1 || !row.userId) throw new ApiError(400, 'INVALID_GRANT', 'Device code has already been used')
  const [user, clientRecord] = await Promise.all([
    prisma.user.findUnique({ where: { id: row.userId } }),
    prisma.client.findUnique({ where: { id: row.clientId }, select: { active: true, grantTypes: true } }),
  ])
  if (!clientRecord?.active) throw new ApiError(400, 'INVALID_GRANT', 'Client is inactive')
  if (!user?.active) throw new ApiError(400, 'INVALID_GRANT', 'User account is inactive')

  const { roles, permissions } = await userTokenGrants(user.id)
  const { sessionId } = await createSession(user.id, ipAddress, userAgent)
  const pair = await issueTokenPair(user.id, user.email, user.username, roles, permissions, sessionId, ipAddress, row.clientId, userAgent, undefined, row.scope ?? undefined)
  const refreshAllowed = parsePermissionList(clientRecord.grantTypes).includes('refresh_token')
  if (!refreshAllowed) await prisma.refreshToken.deleteMany({ where: { tokenHash: sha256Hex(pair.refreshToken) } })
  await logAuditEvent({
    eventType: 'oauth.device_token',
    category: 'AUTHENTICATION',
    actorId: user.id,
    actorType: 'USER',
    actorEmail: user.email,
    clientId: row.clientId,
    ipAddress,
    action: 'device_token',
    outcome: 'SUCCESS',
    detail: { clientId: row.clientId, scope: row.scope },
    source: 'iam-api',
  })
  return {
    accessToken: pair.accessToken,
    ...(refreshAllowed ? { refreshToken: pair.refreshToken } : {}),
    expiresIn: pair.expiresIn,
    ...(row.scope ? { scope: row.scope } : {}),
    userId: user.id,
    email: user.email,
    username: user.username,
    displayName: user.displayName,
    sessionId,
    ...(row.authTime ? { authTime: row.authTime } : {}),
  }
}

/** Delete device sign-ins that expired more than a day ago. */
export async function cleanupExpiredDeviceAuthorizations(): Promise<number> {
  const result = await prisma.deviceAuthorization.deleteMany({ where: { expiresAt: { lt: new Date(Date.now() - 86_400_000) } } })
  return result.count
}
