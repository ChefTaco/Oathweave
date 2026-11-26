import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { envSchema } from '../config/env-schema.js'
import { applyCliDefaults } from './defaults.js'
import { PACKAGE_ROOT } from './paths.js'

// AGENTS.md warns that the CLI and `npm run dev` start with different defaults. Both sets must
// stay named there, so a changed default cannot silently make the warning wrong.
describe('documented defaults', () => {
  const agents = readFileSync(join(PACKAGE_ROOT, '..', '..', 'AGENTS.md'), 'utf8').replace(/\s+/g, ' ')
  const dev = envSchema.parse({
    DATABASE_URL: 'file:/tmp/fixture.db',
    JWT_PRIVATE_KEY_PATH: '/tmp/private.pem',
    JWT_PUBLIC_KEY_PATH: '/tmp/public.pem',
    COOKIE_SECRET: 'x'.repeat(32),
    IAM_AGENT_SECRET: 'x'.repeat(16),
  })
  const cli: Record<string, string | undefined> = { HIVE_HOME: '/tmp/fixture-hive' }
  applyCliDefaults(cli)

  for (const name of ['HOST', 'JWT_ISSUER'] as const) {
    it(`names the CLI and development ${name} defaults in AGENTS.md`, () => {
      expect(cli[name]).toBeDefined()
      expect(agents).toContain(`\`${name}=${cli[name]}\``)
      expect(agents).toContain(`\`${name}=${String(dev[name])}\``)
      expect(cli[name]).not.toBe(String(dev[name]))
    })
  }
})
