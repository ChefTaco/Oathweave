import { mkdir, lstat, realpath, open, unlink } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { randomUUID } from 'node:crypto'

/** A protected server outbox is consumed by the operator's notification service.
 * No raw reset token goes to the requesting browser, logs or the audit stream. */
export async function recoveryOutbox(
  raw = process.env.IAM_RECOVERY_OUTBOX_DIRECTORY,
): Promise<string> {
  if (!raw || !raw.startsWith('/') || resolve(raw) !== raw)
    throw new Error('Recovery delivery is not configured')
  await mkdir(raw, { recursive: true, mode: 0o700 })
  const state = await lstat(raw)
  if (
    !state.isDirectory() ||
    state.isSymbolicLink() ||
    state.uid !== process.getuid?.() ||
    (state.mode & 0o077) !== 0 ||
    (await realpath(raw)) !== raw
  ) {
    throw new Error(
      'Recovery outbox must be an owned directory with mode 0700, without symlinks',
    )
  }
  return raw
}

export async function deliverPasswordRecovery(
  directory: string,
  email: string,
  token: string,
  expiresAt: Date,
): Promise<void> {
  const path = join(directory, randomUUID() + '.json')
  const file = await open(path, 'wx', 0o600)
  try {
    await file.writeFile(
      JSON.stringify({
        schema: 1,
        type: 'password-recovery',
        recipient: email,
        token,
        expiresAt: expiresAt.toISOString(),
      }) + '\n',
    )
    await file.sync()
  } catch (error) {
    await unlink(path).catch(() => {})
    throw error
  } finally {
    await file.close()
  }
  const parent = await open(directory, 'r')
  try {
    await parent.sync()
  } finally {
    await parent.close()
  }
}
