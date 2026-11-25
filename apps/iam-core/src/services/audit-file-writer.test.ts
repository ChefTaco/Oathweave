import { readdir, unlink } from 'node:fs/promises'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { pruneOldAuditFiles, startAuditRetention, stopAuditRetention } from './audit-file-writer.js'

vi.mock('node:fs/promises', () => ({ mkdir: vi.fn(), appendFile: vi.fn(), readdir: vi.fn(), unlink: vi.fn() }))
vi.mock('../config/env.js', () => ({ env: { AUDIT_MAX_AGE_DAYS: 365, AUDIT_LOG_DIR: '/example/audit' } }))

afterEach(() => {
  stopAuditRetention()
  vi.restoreAllMocks()
})

describe('audit file retention logs', () => {
  it('describes filesystem errors without the raw exception or configured path', async () => {
    vi.mocked(readdir).mockRejectedValue(Object.assign(new Error('cannot open /example/audit'), { code: 'EACCES' }))
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await pruneOldAuditFiles()).toBe(0)
    expect(error.mock.calls).toEqual([['[audit-retention] Error pruning files. Check AUDIT_LOG_DIR and its permissions.']])
  })

  it('logs the pruned count and keeps newer audit files', async () => {
    vi.mocked(readdir).mockResolvedValue(['2000-01-01.jsonl', '2999-01-01.jsonl'] as never)
    vi.mocked(unlink).mockResolvedValue(undefined)
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    startAuditRetention()
    await vi.waitFor(() => expect(log.mock.calls).toEqual([['[audit-retention] Pruned 1 expired file(s)']]))
    expect(unlink).toHaveBeenCalledExactlyOnceWith('/example/audit/2000-01-01.jsonl')
  })
})
