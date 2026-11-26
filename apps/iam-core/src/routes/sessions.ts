import { Hono } from 'hono'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/rbac.js'
import { revokeSession, revokeAllUserSessions, listActiveSessions, deduplicateSessions } from '../services/session-service.js'
import { logAuditEvent } from '../services/audit-service.js'
import { getClientIp } from '../utils/ip.js'
import { ApiError } from '../types/index.js'
import { prisma } from '../db/client.js'
import { assertMayManageUser, resolveActor } from '../services/privilege-guard.js'

export const sessionsRouter = new Hono()

sessionsRouter.use('*', authMiddleware)

sessionsRouter.get('/', requirePermission('iam:sessions:revoke'), async (c) => {
  const sessions = await listActiveSessions()
  return c.json({ sessions })
})

sessionsRouter.delete('/:id', requirePermission('iam:sessions:revoke'), async (c) => {
  const principal = c.get('principal')
  const sessionId = c.req.param('id')
  const session = await prisma.session.findUnique({ where: { id: sessionId }, select: { userId: true } })
  if (!session) throw new ApiError(404, 'NOT_FOUND', 'Session not found')
  // Signing someone out is managing their account: the privilege guard's rules apply.
  await assertMayManageUser(await resolveActor(c), session.userId, 'sign out this user')
  if (!(await revokeSession(sessionId, principal.sub))) {
    throw new ApiError(404, 'NOT_FOUND', 'Session not found')
  }

  await logAuditEvent({
    eventType: 'session.revoked',
    category: 'AUTHENTICATION',
    actorId: principal.sub,
    actorType: principal.actorType,
    actorEmail: principal.email,
    ipAddress: getClientIp(c),
    resourceType: 'session',
    resourceId: sessionId,
    action: 'revoke',
    source: 'iam-api',
  })

  return c.json({ success: true })
})

sessionsRouter.delete('/user/:userId', requirePermission('iam:sessions:revoke'), async (c) => {
  const principal = c.get('principal')
  const userId = c.req.param('userId')
  await assertMayManageUser(await resolveActor(c), userId, 'sign out this user')
  await revokeAllUserSessions(userId, principal.sub)

  await logAuditEvent({
    eventType: 'session.revoke_all',
    category: 'AUTHENTICATION',
    actorId: principal.sub,
    actorType: principal.actorType,
    actorEmail: principal.email,
    ipAddress: getClientIp(c),
    resourceType: 'user',
    resourceId: userId,
    action: 'revoke_all_sessions',
    source: 'iam-api',
  })

  return c.json({ success: true })
})

sessionsRouter.post('/deduplicate', requirePermission('iam:sessions:revoke'), async (c) => {
  const revoked = await deduplicateSessions()
  return c.json({ success: true, revoked })
})
