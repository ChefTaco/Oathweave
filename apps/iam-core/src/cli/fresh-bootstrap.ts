import { createHash } from 'node:crypto'
import {
  existsSync,
  lstatSync,
  openSync,
  closeSync,
  writeFileSync,
  fsyncSync,
  readFileSync,
  unlinkSync,
} from 'node:fs'
import { join, resolve } from 'node:path'

type Source = Record<string, string | undefined>
function fingerprint(source: Source): string {
  const names = Object.keys(source)
    .filter(
      (name) =>
        name.startsWith('SEED_') || name === 'IAM_BROWSER_CLIENT_POLICIES',
    )
    .sort()
  const settings = names.map((name) => [name, source[name]])
  const suite = source.OATHWEAVE_SUITE_BOOTSTRAP_FILE
    ? readFileSync(source.OATHWEAVE_SUITE_BOOTSTRAP_FILE)
    : Buffer.alloc(0)
  return createHash('sha256')
    .update(JSON.stringify(settings))
    .update('\0')
    .update(suite)
    .digest('hex')
}
function syncDirectory(directory: string): void {
  const fd = openSync(directory, 'r')
  try {
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/** A durable first-start intent permits retry only for the same empty database
 * and seed inputs. An existing store without this receipt is never reseeded. */
export function initialBootstrapIntent(
  directory: string,
  database: string,
  source: Source,
): boolean {
  const path = join(directory, '.bootstrap-pending.json')
  if (existsSync(join(directory, '.initialized'))) return false
  if (
    existsSync(path) ||
    (() => {
      try {
        lstatSync(path)
        return true
      } catch {
        return false
      }
    })()
  ) {
    const state = lstatSync(path)
    if (
      !state.isFile() ||
      state.isSymbolicLink() ||
      state.uid !== process.getuid?.() ||
      (state.mode & 0o077) !== 0
    )
      throw new Error(
        'First-start receipt must be an owned, protected regular file',
      )
    const previous: unknown = JSON.parse(readFileSync(path, 'utf8'))
    if (
      !previous ||
      typeof previous !== 'object' ||
      !('schema' in previous) ||
      previous.schema !== 1 ||
      !('database' in previous) ||
      previous.database !== resolve(database) ||
      !('inputsSHA256' in previous) ||
      previous.inputsSHA256 !== fingerprint(source)
    )
      throw new Error(
        'First-start inputs changed; recover the original bootstrap configuration instead of reseeding',
      )
    return true
  }
  if (existsSync(database)) return false
  const fd = openSync(path, 'wx', 0o600)
  try {
    writeFileSync(
      fd,
      JSON.stringify({
        schema: 1,
        database: resolve(database),
        inputsSHA256: fingerprint(source),
      }) + '\n',
    )
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  syncDirectory(directory)
  return true
}
export function finishInitialBootstrap(directory: string): void {
  const path = join(directory, '.bootstrap-pending.json')
  if (!existsSync(path)) return
  unlinkSync(path)
  syncDirectory(directory)
}
