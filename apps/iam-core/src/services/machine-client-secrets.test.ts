import { describe, expect, it } from 'vitest'
import { parseClientPolicies } from './client-policy-schema.js'
import {
  parseMachineClientSecrets,
  reconcileMachineClients,
  type ManagedClientRecord,
  type ManagedClientStore,
  type SecretHasher,
} from './machine-client-secrets.js'
import { argon2Hasher } from './machine-client-store.js'
import { validateEnv } from '../config/env-schema.js'

const policies = parseClientPolicies(
  JSON.stringify({
    'fake-service': {
      audience: 'fake-api',
      permissions: ['fake-api:read'],
      lifetimeSeconds: 300,
      rotationOwner: 'fake-owner',
    },
  }),
)
const secret = 'fake-machine-secret-'.padEnd(40, 'x')

// A plain-text hasher keeps reconciliation tests fast; the argon2 hasher is
// exercised separately below.
const plainHasher: SecretHasher = {
  hash: async (value) => 'hash:' + value,
  verify: async (hash, value) => hash === 'hash:' + value,
}

function memoryStore(records: ManagedClientRecord[] = []) {
  const byId = new Map(records.map((record) => [record.id, { ...record }]))
  const writes: string[] = []
  const store: ManagedClientStore = {
    findById: async (id) => byId.get(id) ?? null,
    findByName: async (name) => {
      const found = [...byId.values()].find((record) => record.name === name)
      return found ? { id: found.id } : null
    },
    create: async ({ id, secretHash }) => {
      writes.push('create:' + id)
      byId.set(id, {
        id,
        name: id,
        clientType: 'confidential',
        grantTypes: '["client_credentials"]',
        redirectUris: '[]',
        secretHash,
        active: true,
      })
    },
    updateSecretHash: async (id, secretHash) => {
      writes.push('update:' + id)
      byId.set(id, { ...byId.get(id)!, secretHash })
    },
  }
  return { store, byId, writes }
}

const managed = (overrides: Partial<ManagedClientRecord> = {}): ManagedClientRecord => ({
  id: 'fake-service',
  name: 'fake-service',
  clientType: 'confidential',
  grantTypes: '["client_credentials"]',
  redirectUris: '[]',
  secretHash: 'hash:' + secret,
  active: true,
  ...overrides,
})

describe('machine client secrets configuration', () => {
  it('is empty when unset and maps configured client IDs to secrets', () => {
    expect(parseMachineClientSecrets(undefined, policies)).toEqual({})
    expect(parseMachineClientSecrets('', policies)).toEqual({})
    expect(parseMachineClientSecrets(JSON.stringify({ 'fake-service': secret }), policies)).toEqual({ 'fake-service': secret })
  })

  it('requires a policy for every managed client', () => {
    expect(() => parseMachineClientSecrets(JSON.stringify({ 'other-service': secret }), policies)).toThrow(/other-service.*no IAM_MACHINE_CLIENT_POLICIES/u)
  })

  it('rejects weak or malformed secrets without echoing any value', () => {
    for (const raw of [
      JSON.stringify({ 'fake-service': 'short-fake-secret' }),
      JSON.stringify({ 'fake-service': secret + ' with space' }),
      JSON.stringify({ 'bad id!': secret }),
      JSON.stringify([secret]),
      '{"fake-service":"' + secret + '"',
    ]) {
      let message = ''
      try {
        parseMachineClientSecrets(raw, policies)
      } catch (error) {
        message = error instanceof Error ? error.message : String(error)
      }
      expect(message).not.toBe('')
      expect(message).not.toContain('fake-machine-secret')
      expect(message).not.toContain('short-fake-secret')
    }
  })

  it('fails startup validation with a message that names the variable but not the secret', () => {
    const base = {
      DATABASE_URL: 'file:/tmp/fake.db',
      JWT_PRIVATE_KEY_PATH: '/tmp/fake-private.pem',
      JWT_PUBLIC_KEY_PATH: '/tmp/fake-public.pem',
      COOKIE_SECRET: 'c'.repeat(32),
      IAM_AGENT_SECRET: 'a'.repeat(16),
      IAM_MACHINE_CLIENT_POLICIES: JSON.stringify({ 'fake-service': { audience: 'fake-api', permissions: ['fake-api:read'], rotationOwner: 'fake-owner' } }),
    }
    expect(validateEnv({ ...base, IAM_MACHINE_CLIENT_SECRETS: JSON.stringify({ 'fake-service': secret }) }).ok).toBe(true)
    const missingPolicy = validateEnv({ ...base, IAM_MACHINE_CLIENT_SECRETS: JSON.stringify({ unlisted: secret }) })
    expect(missingPolicy.ok).toBe(false)
    if (!missingPolicy.ok) {
      expect(missingPolicy.errors.join('\n')).toMatch(/IAM_MACHINE_CLIENT_SECRETS/u)
      expect(missingPolicy.errors.join('\n')).not.toContain('fake-machine-secret')
    }
    const badPolicies = validateEnv({ ...base, IAM_MACHINE_CLIENT_POLICIES: '{"hive-router":{}}' })
    expect(badPolicies.ok).toBe(false)
  })

  it('needs an HTTPS browser issuer before a policy may select it', () => {
    const base = {
      DATABASE_URL: 'file:/tmp/fake.db',
      JWT_PRIVATE_KEY_PATH: '/tmp/fake-private.pem',
      JWT_PUBLIC_KEY_PATH: '/tmp/fake-public.pem',
      COOKIE_SECRET: 'c'.repeat(32),
      IAM_AGENT_SECRET: 'a'.repeat(16),
      IAM_MACHINE_CLIENT_POLICIES: JSON.stringify({ 'fake-service': { audience: 'fake-api', permissions: ['fake-api:act'], rotationOwner: 'fake-owner', issuer: 'browser' } }),
    }
    for (const issuer of [undefined, 'native-identity', 'http://identity.example.com', 'https://identity.example.com/?next=x']) {
      const result = validateEnv({ ...base, ...(issuer ? { IAM_BROWSER_ISSUER: issuer } : {}) })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.errors.join('\n')).toMatch(/IAM_BROWSER_ISSUER/u)
    }
    expect(validateEnv({ ...base, IAM_BROWSER_ISSUER: 'https://identity.example.com' }).ok).toBe(true)
  })
})

describe('machine client reconciliation', () => {
  it('creates a missing client as confidential and client_credentials-only', async () => {
    const { store, byId } = memoryStore()
    expect(await reconcileMachineClients({ 'fake-service': secret }, store, plainHasher)).toEqual([{ id: 'fake-service', outcome: 'created', active: true }])
    expect(byId.get('fake-service')).toMatchObject({ clientType: 'confidential', grantTypes: '["client_credentials"]', redirectUris: '[]', secretHash: 'hash:' + secret })
  })

  it('is idempotent and writes nothing when the stored secret already matches', async () => {
    const { store, writes } = memoryStore([managed()])
    expect(await reconcileMachineClients({ 'fake-service': secret }, store, plainHasher)).toEqual([{ id: 'fake-service', outcome: 'unchanged', active: true }])
    expect(writes).toEqual([])
  })

  it('rotates the stored secret when the configured one changes, and provisions a missing hash', async () => {
    const rotated = memoryStore([managed({ secretHash: 'hash:previous-fake-secret' })])
    expect((await reconcileMachineClients({ 'fake-service': secret }, rotated.store, plainHasher))[0]!.outcome).toBe('secret-updated')
    expect(rotated.byId.get('fake-service')!.secretHash).toBe('hash:' + secret)
    const empty = memoryStore([managed({ secretHash: null })])
    expect((await reconcileMachineClients({ 'fake-service': secret }, empty.store, plainHasher))[0]!.outcome).toBe('secret-provisioned')
  })

  it("keeps an administrator's deactivation", async () => {
    const { store, byId } = memoryStore([managed({ active: false, secretHash: 'hash:previous-fake-secret' })])
    expect(await reconcileMachineClients({ 'fake-service': secret }, store, plainHasher)).toEqual([{ id: 'fake-service', outcome: 'secret-updated', active: false }])
    expect(byId.get('fake-service')!.active).toBe(false)
  })

  it('never takes over a browser, interactive or differently named registration', async () => {
    for (const record of [
      managed({ clientType: 'public' }),
      managed({ grantTypes: '["authorization_code","refresh_token","client_credentials"]' }),
      managed({ redirectUris: '["https://client.example.com/callback"]' }),
      managed({ name: 'renamed-client' }),
      managed({ grantTypes: 'not json' }),
    ]) {
      const { store, writes } = memoryStore([record])
      await expect(reconcileMachineClients({ 'fake-service': secret }, store, plainHasher)).rejects.toThrow(/will not be managed/u)
      expect(writes).toEqual([])
    }
    const { store, writes } = memoryStore([managed({ id: 'another-id', name: 'fake-service' })])
    await expect(reconcileMachineClients({ 'fake-service': secret }, store, plainHasher)).rejects.toThrow(/already named/u)
    expect(writes).toEqual([])
  })

  it('stores an argon2 hash that verifies only the configured secret', async () => {
    const hash = await argon2Hasher.hash(secret)
    expect(hash.startsWith('$argon2id$')).toBe(true)
    expect(hash).not.toContain(secret)
    expect(await argon2Hasher.verify(hash, secret)).toBe(true)
    expect(await argon2Hasher.verify(hash, secret + 'y')).toBe(false)
  })
})
