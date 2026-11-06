import { z } from 'zod'
import type { ClientPolicy } from './client-policy-schema.js'

/**
 * Declarative machine clients. IAM_MACHINE_CLIENT_POLICIES says what a client
 * may receive; IAM_MACHINE_CLIENT_SECRETS supplies the secret of each client the
 * installation itself owns, so a product-to-product credential exists and stays
 * valid without anyone registering or rotating it by hand.
 */
const clientId = z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/)
const secret = z
  .string()
  .min(32)
  .max(512)
  .regex(/^[\x21-\x7e]+$/)
const secretsSchema = z.record(clientId, secret)

export const MANAGED_CLIENT_DESCRIPTION =
  'Machine client managed by IAM_MACHINE_CLIENT_SECRETS'

/** Never echoes a supplied value: errors name only the client ID. */
export function parseMachineClientSecrets(
  raw: string | undefined,
  policies: Readonly<Record<string, ClientPolicy>>,
): Readonly<Record<string, string>> {
  if (raw === undefined || raw.trim() === '') return Object.freeze({})
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('IAM_MACHINE_CLIENT_SECRETS must be a JSON object')
  }
  const result = secretsSchema.safeParse(parsed)
  if (!result.success)
    throw new Error(
      'IAM_MACHINE_CLIENT_SECRETS must map client IDs to secrets of 32 to 512 printable characters',
    )
  for (const id of Object.keys(result.data)) {
    if (!policies[id])
      throw new Error(
        `IAM_MACHINE_CLIENT_SECRETS names ${id}, which has no IAM_MACHINE_CLIENT_POLICIES entry`,
      )
  }
  return Object.freeze(result.data)
}

export interface ManagedClientRecord {
  id: string
  name: string
  clientType: string
  grantTypes: string
  redirectUris: string
  secretHash: string | null
  active: boolean
}

export interface ManagedClientStore {
  findById(id: string): Promise<ManagedClientRecord | null>
  findByName(name: string): Promise<{ id: string } | null>
  create(input: { id: string; secretHash: string }): Promise<void>
  updateSecretHash(id: string, secretHash: string): Promise<void>
}

export interface SecretHasher {
  hash(secret: string): Promise<string>
  verify(hash: string, secret: string): Promise<boolean>
}

export type ReconcileOutcome =
  | 'created'
  | 'secret-provisioned'
  | 'secret-updated'
  | 'unchanged'

export interface ReconcileResult {
  id: string
  outcome: ReconcileOutcome
  active: boolean
}

function jsonList(value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

/** A managed client can only ever be a confidential, client_credentials-only
 * client without redirect URIs. Anything else under the same ID or name is a
 * different registration, which is never converted or overwritten. */
function assertManageable(record: ManagedClientRecord): void {
  const grants = jsonList(record.grantTypes)
  const redirects = jsonList(record.redirectUris)
  if (
    record.id !== record.name ||
    record.clientType !== 'confidential' ||
    !Array.isArray(grants) ||
    grants.length !== 1 ||
    grants[0] !== 'client_credentials' ||
    !Array.isArray(redirects) ||
    redirects.length !== 0
  )
    throw new Error(
      `Client ${record.id} exists but is not a confidential client_credentials-only client; it will not be managed by IAM_MACHINE_CLIENT_SECRETS`,
    )
}

/**
 * Creates each configured client once and keeps its stored secret equal to the
 * configured one. The configuration is the rotation owner: changing a secret
 * there and restarting rotates it. An administrator's deactivation is kept.
 */
export async function reconcileMachineClients(
  secrets: Readonly<Record<string, string>>,
  store: ManagedClientStore,
  hasher: SecretHasher,
): Promise<ReconcileResult[]> {
  const results: ReconcileResult[] = []
  for (const [id, value] of Object.entries(secrets)) {
    const existing = await store.findById(id)
    if (!existing) {
      if (await store.findByName(id))
        throw new Error(
          `Another client is already named ${id}; it will not be managed by IAM_MACHINE_CLIENT_SECRETS`,
        )
      await store.create({ id, secretHash: await hasher.hash(value) })
      results.push({ id, outcome: 'created', active: true })
      continue
    }
    assertManageable(existing)
    if (!existing.secretHash) {
      await store.updateSecretHash(id, await hasher.hash(value))
      results.push({ id, outcome: 'secret-provisioned', active: existing.active })
    } else if (!(await hasher.verify(existing.secretHash, value))) {
      await store.updateSecretHash(id, await hasher.hash(value))
      results.push({ id, outcome: 'secret-updated', active: existing.active })
    } else results.push({ id, outcome: 'unchanged', active: existing.active })
  }
  return results
}
