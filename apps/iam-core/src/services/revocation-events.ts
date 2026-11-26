/**
 * Session revocation events, served as HiveEvent v1 at `GET /api/v1/hive/events`.
 *
 * A suite product that verifies Oathweave tokens caches the session check it made through
 * UserInfo for a short while. Following this feed lets it drop that answer as soon as the
 * session ends (sign-out, an administrator's revocation, refresh-token reuse, a password change
 * or reset, a deactivated or deleted user) instead of when its cache entry expires.
 *
 * Two event types:
 *
 * - `session.revoked`: one session ended. `sourceRef` is `session:<sid>`, where `<sid>` is the
 *   value of the tokens' `sid` (ID token) and `sessionId` (access token) claims.
 * - `user.sessions_revoked`: every session of one user ended (password reset or rotation by an
 *   administrator, revoke-all, deactivation, deletion). `sourceRef` is `user:<sub>`. It follows the
 *   `session.revoked` events of the sessions it ended, and is emitted even when none was live.
 *
 * Both carry the user in `subject.actorId` (Oathweave user IDs fit the HiveEvent identifier
 * pattern; one that does not is left out of `subject` and stays in `sourceRef` or the row).
 * Events hold identifiers only: no token, refresh token, password or address.
 */
import { decodeCursor, encodeCursor, parseFeedQuery, type HiveEvent, type Page } from '@hivemagnus/hive-common/events'
import { prisma } from '../db/client.js'
import { ApiError } from '../types/index.js'

/** Oathweave's product ID in the Hive Registry. */
export const OATHWEAVE_PRODUCT = 'oathweave'
export const SESSION_REVOKED = 'session.revoked'
export const USER_SESSIONS_REVOKED = 'user.sessions_revoked'
/** Events older than this are pruned and not served: seven days. */
export const REVOCATION_EVENT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000
/** HiveXUI's user management page, where sessions are reviewed. */
const LINK_PATH = '/?page=iam-users'
const IDENTIFIER = /^[a-z0-9_-]{2,32}$/

export const REVOCATION_REASONS = [
  'sign_out',
  'self_service',
  'admin',
  'refresh_reuse',
  'password_change',
  'password_reset',
  'user_deactivated',
  'user_deleted',
  'token_revocation',
  'code_replay',
  'code_exchange_race',
  'revoked',
] as const
export type RevocationReason = (typeof REVOCATION_REASONS)[number]

const REASON_TEXT: Readonly<Record<RevocationReason, string>> = {
  sign_out: 'signed out',
  self_service: 'ended by its user',
  admin: 'revoked by an administrator',
  refresh_reuse: 'revoked after a refresh token was reused',
  password_change: 'ended by a password change',
  password_reset: 'ended by a password reset',
  user_deactivated: 'ended because the user was deactivated',
  user_deleted: 'ended because the user was deleted',
  token_revocation: 'revoked through token revocation',
  code_replay: 'revoked after an authorization code was replayed',
  code_exchange_race: 'ended after a failed authorization code exchange',
  revoked: 'revoked',
}
/** Reasons that point at a stolen or replayed credential. */
const WARNING_REASONS: ReadonlySet<RevocationReason> = new Set(['refresh_reuse', 'code_replay'])

export interface RevocationRecord {
  readonly type: typeof SESSION_REVOKED | typeof USER_SESSIONS_REVOKED
  readonly userId: string
  readonly sessionId?: string | null
  readonly reason: RevocationReason
}

/** The part of a Prisma client (or transaction client) that records events. */
export interface RevocationEventWriter {
  revocationEvent: { createMany(args: { data: { type: string; userId: string; sessionId: string | null; reason: string }[] }): Promise<unknown> }
}

/** Record revocation events. Pass the transaction that revokes, so both commit together. */
export async function recordRevocationEvents(db: RevocationEventWriter, records: readonly RevocationRecord[]): Promise<void> {
  if (records.length === 0) return
  await db.revocationEvent.createMany({
    data: records.map(record => ({
      type: record.type,
      userId: record.userId,
      sessionId: record.type === SESSION_REVOKED ? (record.sessionId ?? null) : null,
      reason: record.reason,
    })),
  })
}

export interface RevocationEventRow {
  seq: number
  id: string
  type: string
  sessionId: string | null
  userId: string
  reason: string
  occurredAt: Date
}

function reasonOf(value: string): RevocationReason {
  return (REVOCATION_REASONS as readonly string[]).includes(value) ? (value as RevocationReason) : 'revoked'
}

/** The HiveEvent v1 for a stored row; undefined for a row this version cannot describe. */
export function revocationHiveEvent(row: RevocationEventRow): HiveEvent | undefined {
  const reason = reasonOf(row.reason)
  const subject = IDENTIFIER.test(row.userId) ? { subject: { actorId: row.userId } } : {}
  const base = {
    id: `${OATHWEAVE_PRODUCT}:revocation:${row.id}`,
    product: OATHWEAVE_PRODUCT,
    severity: WARNING_REASONS.has(reason) ? ('warning' as const) : ('info' as const),
    occurredAt: row.occurredAt.toISOString(),
    ...subject,
    link: { product: OATHWEAVE_PRODUCT, path: LINK_PATH },
  }
  if (row.type === SESSION_REVOKED && row.sessionId)
    return {
      ...base,
      type: SESSION_REVOKED,
      title: 'Session revoked',
      summary: `A session of user ${row.userId} was ${REASON_TEXT[reason]}.`,
      sourceRef: `session:${row.sessionId}`,
    }
  if (row.type === USER_SESSIONS_REVOKED)
    return {
      ...base,
      type: USER_SESSIONS_REVOKED,
      title: 'All sessions of a user revoked',
      summary: `Every session of user ${row.userId} was ${REASON_TEXT[reason]}.`,
      sourceRef: `user:${row.userId}`,
    }
  return undefined
}

function feedCursor(seq: number): string {
  return encodeCursor({ s: seq })
}

/** The sequence a cursor from this feed points after; a 400 for anything else. */
function cursorSeq(cursor: string): number {
  let value: Record<string, string | number>
  try {
    value = decodeCursor(cursor)
  } catch {
    throw new ApiError(400, 'INVALID_CURSOR', 'The cursor is not valid')
  }
  const seq = value['s']
  if (Object.keys(value).length !== 1 || typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0)
    throw new ApiError(400, 'INVALID_CURSOR', 'The cursor is not valid')
  return seq
}

/**
 * One page of the feed, oldest first. `after` is an opaque cursor from an earlier page;
 * `nextCursor` is null on the last page. The order is the commit order of the revocations.
 */
export async function revocationEventPage(query: URLSearchParams, now: number = Date.now()): Promise<Page<HiveEvent>> {
  let after: string | undefined
  let limit: number
  try {
    ;({ after, limit } = parseFeedQuery(query, { defaultLimit: 100, maxLimit: 200 }))
  } catch (error) {
    throw new ApiError(400, 'INVALID_QUERY', error instanceof Error ? error.message : 'The query is not valid')
  }
  const seq = after === undefined ? undefined : cursorSeq(after)
  const rows = await prisma.revocationEvent.findMany({
    where: {
      ...(seq !== undefined ? { seq: { gt: seq } } : {}),
      occurredAt: { gte: new Date(now - REVOCATION_EVENT_RETENTION_MS) },
    },
    orderBy: { seq: 'asc' },
    take: limit + 1,
  })
  const page = rows.slice(0, limit)
  const data: HiveEvent[] = []
  for (const row of page) {
    const event = revocationHiveEvent(row)
    if (event) data.push(event)
  }
  const last = page.at(-1)
  return { data, nextCursor: rows.length > limit && last ? feedCursor(last.seq) : null }
}

/** Delete events past the retention window. Returns how many were deleted. */
export async function pruneRevocationEvents(now: number = Date.now()): Promise<number> {
  const { count } = await prisma.revocationEvent.deleteMany({
    where: { occurredAt: { lt: new Date(now - REVOCATION_EVENT_RETENTION_MS) } },
  })
  return count
}
