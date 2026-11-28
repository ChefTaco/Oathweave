import { describe, expect, it } from 'vitest'
import { isActorClaim } from './actor-claim.js'
import { parseTokenExchangePolicies } from './token-exchange-policy.js'

describe('IAM_TOKEN_EXCHANGE_POLICIES', () => {
  const audiences = { memory: { permissions: ['memory:read'] } }

  it('defaults to access-token subjects, five-minute tokens and no actors', () => {
    expect(parseTokenExchangePolicies(JSON.stringify({ gateway: { audiences } })).gateway).toEqual({
      subjectAudiences: [],
      subjectTokenTypes: ['access_token'],
      audiences: { memory: { permissions: ['memory:read'], lifetimeSeconds: 300, actors: [] } },
    })
  })

  it('accepts refresh-token subjects and listed actors', () => {
    const policy = parseTokenExchangePolicies(JSON.stringify({
      gateway: { subjectTokenTypes: ['refresh_token'], audiences: { memory: { permissions: ['memory:read'], actors: ['agent-runner'] } } },
    })).gateway
    expect(policy?.subjectTokenTypes).toEqual(['refresh_token'])
    expect(policy?.audiences['memory']?.actors).toEqual(['agent-runner'])
  })

  it('refuses ID-token subjects, bad actors, longer lifetimes and the reserved enrollment identity', () => {
    for (const policy of [
      { gateway: { subjectTokenTypes: ['id_token'], audiences } },
      { gateway: { subjectTokenTypes: [], audiences } },
      { gateway: { audiences: { memory: { permissions: ['memory:read'], actors: ['not a client'] } } } },
      { gateway: { audiences: { memory: { permissions: ['memory:read'], lifetimeSeconds: 901 } } } },
      { gateway: { audiences: { memory: { permissions: ['memory:read'], unknown: true } } } },
      { 'oathweave-enrollment': { audiences } },
    ]) {
      expect(() => parseTokenExchangePolicies(JSON.stringify(policy))).toThrow()
    }
  })
})

describe('act claims', () => {
  it('accepts an actor, and an actor with the client that relayed it', () => {
    expect(isActorClaim({ sub: 'gateway' })).toBe(true)
    expect(isActorClaim({ sub: 'agent', act: { sub: 'gateway' } })).toBe(true)
    expect(isActorClaim({ sub: 'sa-1', client_id: 'agent' })).toBe(true)
  })

  it('refuses anything else', () => {
    for (const value of [undefined, null, 'gateway', [], {}, { sub: '' }, { sub: 1 }, { sub: 'a', client_id: '' }, { sub: 'a', other: 'b' }, { sub: 'a', act: 'b' }, { sub: 'a', act: { sub: 'b', act: { sub: 'c' } } }]) {
      expect(isActorClaim(value)).toBe(false)
    }
  })
})
