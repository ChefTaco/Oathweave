import { nanoid } from 'nanoid'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { ApiError } from '../types/index.js'
import { computeSessionRisk, deriveDeviceFingerprint } from './session-risk-service.js'
import type { Prisma } from '../db/generated/index.js'
import { recordRevocationEvents, SESSION_REVOKED, USER_SESSIONS_REVOKED, type RevocationReason } from './revocation-events.js'

export async function createSession(
  userId: string,
  ipAddress?: string,
  userAgent?: string,
): Promise<{ sessionId: string; riskScore: number; riskFactors: string[] }> {
  // Network/browser metadata is shared by independent clients behind NAT.
  // Retain it for risk analysis, never as authority to revoke another session.
  const { score, factors } = await computeSessionRisk({ userId, ...(ipAddress !== undefined ? { ipAddress } : {}), ...(userAgent !== undefined ? { userAgent } : {}) })
  const fingerprint = deriveDeviceFingerprint(userAgent, ipAddress)

  const sessionId = nanoid()
  await prisma.session.create({
    data: {
      id: sessionId,
      userId,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      riskScore: score,
      riskFactors: factors.length > 0 ? JSON.stringify(factors) : null,
      deviceFingerprint: fingerprint ?? null,
      expiresAt: new Date(Date.now() + env.JWT_REFRESH_TTL * 1000),
    },
  })
  return { sessionId, riskScore: score, riskFactors: factors }
}

export interface RevokeOptions {
  /** Why the session ends, for the revocation event. `revoked` when not given. */
  readonly reason?: RevocationReason
}

/**
 * Revokes a session and its refresh tokens. Returns false when no such session
 * exists. An already revoked session keeps its original revocation record. A session
 * revoked by this call records a `session.revoked` event in the same transaction.
 */
export async function revokeSession(sessionId: string, revokedBy?: string, options: RevokeOptions = {}): Promise<boolean> {
  return prisma.$transaction(async (transaction) => {
    const session = await transaction.session.findUnique({ where: { id: sessionId }, select: { userId: true, revokedAt: true } })
    if (!session) return false
    if (!session.revokedAt) {
      // Conditional, so two racing revocations record one event.
      const { count } = await transaction.session.updateMany({
        where: { id: sessionId, revokedAt: null },
        data: { revokedAt: new Date(), ...(revokedBy !== undefined ? { revokedBy } : {}) },
      })
      if (count > 0)
        await recordRevocationEvents(transaction, [{ type: SESSION_REVOKED, userId: session.userId, sessionId, reason: options.reason ?? 'revoked' }])
    }
    // Also revoke all refresh tokens tied to this session
    await transaction.refreshToken.updateMany({
      where: { sessionId, revokedAt: null },
      data: { revokedAt: new Date() },
    })
    return true
  })
}

/**
 * Revokes every live session of a user and its refresh tokens, then records a
 * `user.sessions_revoked` event (also when no session was live, so a product drops whatever
 * it cached for the user).
 */
export async function revokeAllUserSessions(userId: string, revokedBy?: string, options: RevokeOptions = {}): Promise<void> {
  const sessions = await prisma.session.findMany({
    where: { userId, revokedAt: null },
    select: { id: true },
  })
  for (const s of sessions) {
    await revokeSession(s.id, revokedBy, options)
  }
  await recordRevocationEvents(prisma, [{ type: USER_SESSIONS_REVOKED, userId, reason: options.reason ?? 'revoked' }])
}

/**
 * Inside a caller's transaction: revoke every live session of a user (not their refresh
 * tokens, which the caller handles) and record the events with it.
 */
export async function revokeUserSessionsInTransaction(
  transaction: Pick<Prisma.TransactionClient, 'session' | 'revocationEvent'>,
  userId: string,
  revokedBy: string,
  reason: RevocationReason,
): Promise<void> {
  const live = await transaction.session.findMany({ where: { userId, revokedAt: null }, select: { id: true } })
  if (live.length > 0)
    await transaction.session.updateMany({
      where: { id: { in: live.map(s => s.id) }, revokedAt: null },
      data: { revokedAt: new Date(), revokedBy },
    })
  await recordRevocationEvents(transaction, [
    ...live.map(s => ({ type: SESSION_REVOKED, userId, sessionId: s.id, reason }) as const),
    { type: USER_SESSIONS_REVOKED, userId, reason },
  ])
}

export async function listActiveSessions(userId?: string) {
  return prisma.session.findMany({
    where: {
      ...(userId ? { userId } : {}),
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    include: { user: { select: { email: true, username: true, displayName: true } } },
    orderBy: { createdAt: 'desc' },
  })
}

/** Retained compatibility entrypoint: callers must select exact session IDs. */
export async function deduplicateSessions(): Promise<number> {
  throw new ApiError(
    409,
    'EXPLICIT_SESSION_SELECTION_REQUIRED',
    'IP addresses and browser metadata do not identify duplicate sessions. Review active sessions and revoke explicit session IDs instead.',
  )
}
