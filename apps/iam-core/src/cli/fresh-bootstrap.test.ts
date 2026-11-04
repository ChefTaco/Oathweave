import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  rmSync,
  chmodSync,
  symlinkSync,
  existsSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it } from 'vitest'
import {
  initialBootstrapIntent,
  finishInitialBootstrap,
} from './fresh-bootstrap.js'
const roots: string[] = []
const fresh = () => {
  const root = mkdtempSync(join(tmpdir(), 'oathweave-first-start-'))
  roots.push(root)
  return root
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true })
})
it('resumes an interrupted fresh database with identical seed inputs and removes only the intent after completion', () => {
  const directory = fresh(),
    database = join(directory, 'identity.db'),
    source = { SEED_ADMIN_PASSWORD: 'obviously-fake-initial-password' }
  expect(initialBootstrapIntent(directory, database, source)).toBe(true)
  writeFileSync(database, 'synthetic database')
  expect(initialBootstrapIntent(directory, database, source)).toBe(true)
  expect(
    readFileSync(join(directory, '.bootstrap-pending.json'), 'utf8'),
  ).not.toContain(source.SEED_ADMIN_PASSWORD)
  writeFileSync(join(directory, '.initialized'), '{}')
  finishInitialBootstrap(directory)
  expect(initialBootstrapIntent(directory, database, source)).toBe(false)
  expect(readFileSync(database, 'utf8')).toBe('synthetic database')
})
it('never gives an existing empty store a new seed receipt', () => {
  const directory = fresh(),
    database = join(directory, 'existing.db')
  writeFileSync(database, 'retained empty store')
  expect(initialBootstrapIntent(directory, database, {})).toBe(false)
  expect(existsSync(join(directory, '.bootstrap-pending.json'))).toBe(false)
})
it('rejects changed credentials and changed suite registration inputs on retry', () => {
  const directory = fresh(),
    database = join(directory, 'identity.db'),
    suite = join(directory, 'suite.json')
  writeFileSync(suite, '{"schema":1}')
  const source = {
    SEED_ADMIN_PASSWORD: 'obviously-fake-initial-password',
    OATHWEAVE_SUITE_BOOTSTRAP_FILE: suite,
  }
  initialBootstrapIntent(directory, database, source)
  expect(() =>
    initialBootstrapIntent(directory, database, {
      ...source,
      SEED_ADMIN_PASSWORD: 'different-fake-password',
    }),
  ).toThrow(/inputs changed/)
  writeFileSync(suite, '{"schema":2}')
  expect(() => initialBootstrapIntent(directory, database, source)).toThrow(
    /inputs changed/,
  )
})
it('refuses a readable-by-others or linked first-start receipt', () => {
  const directory = fresh(),
    database = join(directory, 'identity.db'),
    path = join(directory, '.bootstrap-pending.json')
  initialBootstrapIntent(directory, database, {})
  chmodSync(path, 0o644)
  expect(() => initialBootstrapIntent(directory, database, {})).toThrow(
    /protected/,
  )
  rmSync(path)
  symlinkSync('/dev/null', path)
  expect(() => initialBootstrapIntent(directory, database, {})).toThrow(
    /protected/,
  )
})
