import { describe, expect, it } from 'vitest'
import { parseArgs, UsageError } from './args.js'

describe('hive-iam-server argument parsing', () => {
  it('defaults to start with migrations enabled', () => {
    expect(parseArgs([])).toEqual({ command: 'start', envFiles: [], migrate: true, relaxAuthLimits: false })
  })

  it('accepts commands and both --env-file forms, in order', () => {
    expect(parseArgs(['check', '--env-file', 'a.env', '--env-file=b.env'])).toEqual({
      command: 'check',
      envFiles: ['a.env', 'b.env'],
      migrate: true,
      relaxAuthLimits: false,
    })
    expect(parseArgs(['--env-file', 'x.env', 'start', '--no-migrate'])).toMatchObject({ command: 'start', migrate: false })
  })

  it('accepts --relax-auth-limits only for start', () => {
    expect(parseArgs(['--relax-auth-limits'])).toMatchObject({ command: 'start', relaxAuthLimits: true })
    expect(parseArgs(['start', '--relax-auth-limits'])).toMatchObject({ command: 'start', relaxAuthLimits: true })
    expect(parseArgs(['start'])).toMatchObject({ relaxAuthLimits: false })
    expect(() => parseArgs(['check', '--relax-auth-limits'])).toThrow(/only to the start command/)
    expect(() => parseArgs(['--relax-auth-limits', 'migrate'])).toThrow(/only to the start command/)
  })

  it('handles help and version anywhere', () => {
    expect(parseArgs(['check', '--help']).command).toBe('help')
    expect(parseArgs(['-v']).command).toBe('version')
    expect(parseArgs(['--version']).command).toBe('version')
  })

  it('rejects unknown input', () => {
    expect(() => parseArgs(['serve'])).toThrow(UsageError)
    expect(() => parseArgs(['--port', '1'])).toThrow(/unknown option/)
    expect(() => parseArgs(['--env-file'])).toThrow(/needs a path/)
    expect(() => parseArgs(['--env-file='])).toThrow(/needs a path/)
    expect(() => parseArgs(['start', 'check'])).toThrow(/unexpected argument/)
  })
})
