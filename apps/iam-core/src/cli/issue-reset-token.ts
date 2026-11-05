import { UsageError } from './args.js'

export interface ResetTokenOptions {
  account: string
  username: string
  tokenSha256: string
  installation: string
  ttlSeconds: number
}

export const DEFAULT_RESET_TOKEN_TTL_SECONDS = 24 * 60 * 60
const MAXIMUM_RESET_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60

/** The raw token never reaches this process: the operator's tool generates it and
 * supplies only its SHA-256, the same digest `POST /auth/reset-password` looks up. */
export function parseIssueResetToken(args: readonly string[]): ResetTokenOptions {
  const values = new Map<string, string>()
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]!
    const value = args[index + 1]
    if (!['--account', '--username', '--token-sha256', '--installation', '--ttl-seconds'].includes(name))
      throw new UsageError(`unknown option ${name}`)
    if (!value || value.startsWith('--')) throw new UsageError(`${name} needs a value`)
    if (values.has(name)) throw new UsageError(`${name} was given twice`)
    values.set(name, value)
  }
  const required = (name: string): string => {
    const value = values.get(name)
    if (!value) throw new UsageError(`issue-reset-token needs ${name}`)
    return value
  }
  const tokenSha256 = required('--token-sha256')
  if (!/^[a-f0-9]{64}$/.test(tokenSha256))
    throw new UsageError('--token-sha256 must be a SHA-256 digest; the raw token is never accepted')
  const ttlSeconds = Number(values.get('--ttl-seconds') ?? DEFAULT_RESET_TOKEN_TTL_SECONDS)
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAXIMUM_RESET_TOKEN_TTL_SECONDS)
    throw new UsageError(`--ttl-seconds must be a whole number from 1 to ${MAXIMUM_RESET_TOKEN_TTL_SECONDS}`)
  return {
    account: required('--account'),
    username: required('--username'),
    tokenSha256,
    installation: required('--installation'),
    ttlSeconds,
  }
}

interface ResetTokenTransaction {
  user: {
    findUnique(arguments_: { where: { id: string } }): Promise<{ id: string; username: string; active: boolean } | null>
  }
  passwordResetToken: {
    updateMany(arguments_: { where: { userId: string; usedAt: null }; data: { usedAt: Date } }): Promise<unknown>
    create(arguments_: { data: { userId: string; tokenHash: string; expiresAt: Date } }): Promise<unknown>
  }
}

export interface ResetTokenDatabase {
  $transaction<T>(work: (transaction: ResetTokenTransaction) => Promise<T>): Promise<T>
  passwordResetToken: { updateMany(arguments_: { where: { tokenHash: string; usedAt: null }; data: { usedAt: Date } }): Promise<unknown> }
}

/** Issues a one-use token for exactly the named account through the password-recovery
 * table. It changes no password, session, MFA enrolment or other account. The reset
 * itself stays on the throttled `POST /auth/reset-password` route, which enforces the
 * password policy and history and records its own audit event. */
export async function issueResetToken(
  database: ResetTokenDatabase,
  options: ResetTokenOptions,
  audit: (event: Record<string, unknown>) => Promise<unknown>,
  now: Date = new Date(),
): Promise<{ expiresAt: string }> {
  const expiresAt = new Date(now.getTime() + options.ttlSeconds * 1000)
  await database.$transaction(async (transaction) => {
    const user = await transaction.user.findUnique({ where: { id: options.account } })
    if (!user || user.username !== options.username || !user.active)
      throw new Error('No active account has exactly this ID and username; no token was issued')
    // As with recovery, only the newest token for an account stays usable.
    await transaction.passwordResetToken.updateMany({
      where: { userId: user.id, usedAt: null },
      data: { usedAt: now },
    })
    await transaction.passwordResetToken.create({
      data: { userId: user.id, tokenHash: options.tokenSha256, expiresAt },
    })
  })
  try {
    await audit({
      eventType: 'auth.password_reset_issued',
      category: 'AUTHENTICATION',
      actorId: options.account,
      actorType: 'SYSTEM',
      action: 'password_reset_issue',
      outcome: 'SUCCESS',
      source: 'iam-cli',
      detail: { installation: options.installation, expiresAt: expiresAt.toISOString(), channel: 'operator' },
    })
  } catch (error) {
    // An unrecorded token must not stay usable.
    await database.passwordResetToken.updateMany({
      where: { tokenHash: options.tokenSha256, usedAt: null },
      data: { usedAt: new Date() },
    })
    throw error
  }
  return { expiresAt: expiresAt.toISOString() }
}
