import { Hono } from 'hono'
import { authMiddleware } from '../middleware/auth.js'
import { revocationEventPage } from '../services/revocation-events.js'

/**
 * `GET /api/v1/hive/events?after=<cursor>&limit=<n>`: session revocations as HiveEvent v1, for
 * suite products that cache session checks (see services/revocation-events.ts). Readable with
 * `iam:tokens:introspect`, the permission a backend validates tokens with, or
 * `iam:sessions:revoke`.
 */
export const FEED_PERMISSIONS = ['iam:tokens:introspect', 'iam:sessions:revoke'] as const

export const hiveEventsRouter = new Hono()

hiveEventsRouter.get('/events', authMiddleware, async (c) => {
  const principal = c.get('principal')
  if (!FEED_PERMISSIONS.some((permission) => principal.permissions.includes(permission))) {
    return c.json({ error: 'FORBIDDEN', message: `Missing permissions: one of ${FEED_PERMISSIONS.join(', ')}` }, 403)
  }
  const page = await revocationEventPage(new URL(c.req.url).searchParams)
  c.header('Cache-Control', 'no-store')
  return c.json(page)
})
