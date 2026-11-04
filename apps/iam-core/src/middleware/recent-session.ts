import type { MiddlewareHandler } from 'hono'
import { prisma } from '../db/client.js'

/** Factor changes require a recent interactive authentication for this account. */
export const requireRecentSession: MiddlewareHandler = async (c, next) => {
  const principal = c.get('principal')
  if (principal.actorType !== 'USER' || !principal.sessionId)
    return c.json(
      { error: 'FORBIDDEN', message: 'Interactive session required' },
      403,
    )
  const session = await prisma.session.findFirst({
    where: {
      id: principal.sessionId,
      userId: principal.sub,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    select: { createdAt: true, stepUpVerifiedAt: true },
  })
  if (!session) return c.json({ error: 'UNAUTHORIZED' }, 401)
  if (
    Date.now() - (session.stepUpVerifiedAt ?? session.createdAt).getTime() >
    15 * 60 * 1000
  )
    return c.json(
      {
        error: 'STEP_UP_REQUIRED',
        message: 'Verify your identity before changing authentication factors',
      },
      403,
    )
  return next()
}
