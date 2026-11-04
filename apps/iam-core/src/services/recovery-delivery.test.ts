import {
  mkdtemp,
  chmod,
  readFile,
  readdir,
  rm,
  lstat,
  symlink,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { recoveryOutbox, deliverPasswordRecovery } from './recovery-delivery.js'
it('keeps recovery instructions private and rejects permissive or linked delivery directories', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'oathweave-recovery-'))
  try {
    expect(await recoveryOutbox(directory)).toBe(directory)
    await deliverPasswordRecovery(
      directory,
      'alice@example.com',
      'obviously-fake-recovery-code',
      new Date('2030-01-01T00:00:00Z'),
    )
    const files = await readdir(directory)
    expect(files).toHaveLength(1)
    const file = join(directory, files[0]!)
    expect((await lstat(file)).mode & 0o077).toBe(0)
    expect(JSON.parse(await readFile(file, 'utf8'))).toMatchObject({
      recipient: 'alice@example.com',
      token: 'obviously-fake-recovery-code',
    })
    await chmod(directory, 0o755)
    await expect(recoveryOutbox(directory)).rejects.toThrow('0700')
    await chmod(directory, 0o700)
    await symlink(directory, join(directory, 'linked'))
    await expect(recoveryOutbox(join(directory, 'linked'))).rejects.toThrow()
    await expect(recoveryOutbox('relative/path')).rejects.toThrow(
      'not configured',
    )
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
