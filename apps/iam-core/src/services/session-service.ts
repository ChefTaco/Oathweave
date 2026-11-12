import { nanoid } from 'nanoid'
import { prisma } from '../db/client.js'
import { env } from '../config/env.js'
import { ApiError } from '../types/index.js'
import { computeSessionRisk, deriveDeviceFingerprint } from './session-risk-service.js'

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

export async function revokeSession(sessionId: string, revokedBy?: string): Promise<void> {
  await prisma.session.update({
    where: { id: sessionId },
    data: { revokedAt: new Date(), ...(revokedBy !== undefined ? { revokedBy } : {}) },
  })
  // Also revoke all refresh tokens tied to this session
  await prisma.refreshToken.updateMany({
    where: { sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  })
}

export async function revokeAllUserSessions(userId: string, revokedBy?: string): Promise<void> {
  const sessions = await prisma.session.findMany({
    where: { userId, revokedAt: null },
    select: { id: true },
  })
  for (const s of sessions) {
    await revokeSession(s.id, revokedBy)
  }
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
