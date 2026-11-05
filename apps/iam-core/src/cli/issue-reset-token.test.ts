import { describe, expect, it, vi } from 'vitest'
import { UsageError } from './args.js'
import { DEFAULT_RESET_TOKEN_TTL_SECONDS, issueResetToken, parseIssueResetToken, type ResetTokenDatabase } from './issue-reset-token.js'

const digest = 'a'.repeat(64)
const argv = ['--account', 'user-1', '--username', 'admin', '--token-sha256', digest, '--installation', 'fixture']

function database(user: { id: string; username: string; active: boolean } | null) {
  const tokens = { updateMany: vi.fn(async () => ({ count: 0 })), create: vi.fn(async () => ({})) }
  const db = {
    $transaction: async (work: (transaction: never) => Promise<unknown>) =>
      work({ user: { findUnique: async () => user }, passwordResetToken: tokens } as never),
    passwordResetToken: tokens,
  } as unknown as ResetTokenDatabase
  return { db, tokens }
}

describe('issue-reset-token', () => {
  it('accepts only a digest and defaults to a day', () => {
    expect(parseIssueResetToken(argv).ttlSeconds).toBe(DEFAULT_RESET_TOKEN_TTL_SECONDS)
    expect(() => parseIssueResetToken(argv.map((value) => (value === digest ? 'raw-token' : value)))).toThrow(UsageError)
    expect(() => parseIssueResetToken([...argv, '--password', 'x'])).toThrow(UsageError)
    expect(() => parseIssueResetToken([...argv, '--ttl-seconds', '999999999'])).toThrow(UsageError)
    expect(() => parseIssueResetToken(argv.slice(0, 2))).toThrow(UsageError)
  })

  it('stores the hash, retires older tokens and audits without the digest', async () => {
    const { db, tokens } = database({ id: 'user-1', username: 'admin', active: true })
    const audit = vi.fn(async () => undefined)
    const now = new Date('2030-01-01T00:00:00.000Z')
    const { expiresAt } = await issueResetToken(db, parseIssueResetToken(argv), audit, now)
    expect(expiresAt).toBe('2030-01-02T00:00:00.000Z')
    expect(tokens.updateMany).toHaveBeenCalledWith({ where: { userId: 'user-1', usedAt: null }, data: { usedAt: now } })
    expect(tokens.create).toHaveBeenCalledWith({ data: { userId: 'user-1', tokenHash: digest, expiresAt: new Date(expiresAt) } })
    expect(JSON.stringify(audit.mock.calls)).not.toContain(digest)
    expect(audit.mock.calls[0]).toMatchObject([{ eventType: 'auth.password_reset_issued', actorId: 'user-1' }])
  })

  it('refuses a mismatched, missing or disabled account', async () => {
    for (const user of [null, { id: 'user-1', username: 'other', active: true }, { id: 'user-1', username: 'admin', active: false }]) {
      const { db, tokens } = database(user)
      await expect(issueResetToken(db, parseIssueResetToken(argv), async () => undefined)).rejects.toThrow('no token was issued')
      expect(tokens.create).not.toHaveBeenCalled()
    }
  })

  it('retires the token when the audit record cannot be written', async () => {
    const { db, tokens } = database({ id: 'user-1', username: 'admin', active: true })
    await expect(issueResetToken(db, parseIssueResetToken(argv), async () => { throw new Error('queue down') })).rejects.toThrow('queue down')
    expect(tokens.updateMany).toHaveBeenLastCalledWith({ where: { tokenHash: digest, usedAt: null }, data: { usedAt: expect.any(Date) } })
  })
})
