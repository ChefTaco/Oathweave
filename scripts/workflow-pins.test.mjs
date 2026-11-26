// Third-party GitHub Actions run with the workflow's token and secrets, so each is pinned to a
// full commit SHA (a tag can be moved). Local reusable workflows (./...) are exempt.
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

const directory = join(import.meta.dirname, '..', '.github', 'workflows')

test('every third-party action is pinned to a commit SHA', () => {
  const unpinned = []
  for (const file of readdirSync(directory).filter((name) => /\.ya?ml$/.test(name))) {
    for (const [index, line] of readFileSync(join(directory, file), 'utf8').split('\n').entries()) {
      const match = /^\s*(?:-\s*)?uses:\s*([^\s#]+)/.exec(line)
      if (!match || match[1].startsWith('./')) continue
      if (!/@[0-9a-f]{40}$/.test(match[1])) unpinned.push(`${file}:${index + 1} ${match[1]}`)
    }
  }
  assert.deepEqual(unpinned, [])
})
