import Database from '../db/sqlite.js'
import argon2 from 'argon2'
import { nanoid } from 'nanoid'
import { readFileSync } from 'node:fs'
import { request } from 'node:https'
import { z } from 'zod'
import { env } from '../config/env.js'
import { sqlitePathFromUrl } from '../cli/paths.js'
import { ApiError, type Principal } from '../types/index.js'
import { enrollmentCipher } from './enrollment-cipher.js'
import { enrollmentDelegation } from './enrollment-delegation.js'
import { EnrollmentStore, enrollmentDigest, type Action, type Policy } from './enrollment-store.js'

const endpoint = z.object({ url: z.url().refine(value => { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && !url.pathname.includes('..') }), caFile: z.string().regex(/^\//).optional() }).strict()
export const enrollmentProductsSchema = z.object({ emberpath: endpoint, hivemem: endpoint }).strict()
const installationIdSchema = z.string().min(1).max(64).regex(/^[a-z0-9][a-z0-9-]*$/)
export interface EnrollmentSettings { installationId: string; products: z.infer<typeof enrollmentProductsSchema>; operatorSubjects?: string[] }
export function enrollmentConfigurations(source: NodeJS.ProcessEnv = process.env): Record<string,EnrollmentSettings> {
  if (source.IAM_ENROLLMENT_INSTALLATIONS_JSON) {
    if (source.IAM_ENROLLMENT_PRODUCTS_JSON || source.IAM_ENROLLMENT_INSTALLATION_ID) throw new Error('Choose explicit installation namespaces or the legacy single-installation enrollment configuration, never both')
    if (!source.IAM_BROWSER_ISSUER) throw new Error('Enrollment delegation requires IAM_BROWSER_ISSUER')
    const entries = z.record(installationIdSchema, z.object({ products: enrollmentProductsSchema, operatorSubjects: z.array(z.string().min(1).max(200)).min(1).max(1000) }).strict()).parse(JSON.parse(source.IAM_ENROLLMENT_INSTALLATIONS_JSON))
    if (!Object.keys(entries).length || Object.keys(entries).length > 100) throw new Error('Configure between 1 and 100 explicit installation namespaces')
    const endpoints = new Set<string>()
    for (const entry of Object.values(entries)) for (const product of ['emberpath','hivemem'] as const) { const key = product + ':' + new URL(entry.products[product].url).href.replace(/\/$/,''); if (endpoints.has(key)) throw new Error('Independent installation namespaces must not alias the same product API endpoint'); endpoints.add(key) }
    return Object.fromEntries(Object.entries(entries).map(([installationId,entry]) => [installationId,{installationId,...entry}]))
  }
  if (!source.IAM_ENROLLMENT_PRODUCTS_JSON && !source.IAM_ENROLLMENT_INSTALLATION_ID) return {}
  if (!source.IAM_BROWSER_ISSUER) throw new Error('Enrollment delegation requires IAM_BROWSER_ISSUER')
  const installationId = installationIdSchema.parse(source.IAM_ENROLLMENT_INSTALLATION_ID)
  return { [installationId]: { installationId, products: enrollmentProductsSchema.parse(JSON.parse(source.IAM_ENROLLMENT_PRODUCTS_JSON ?? '{}')) } }
}
export function enrollmentSettings(installationId?: string, subject?: string): EnrollmentSettings | undefined {
  const configurations = enrollmentConfigurations(), names = Object.keys(configurations)
  if (!names.length) return undefined
  if (!installationId && names.length !== 1) throw new ApiError(400,'INSTALLATION_REQUIRED','Select the exact installation namespace before accessing its identities')
  const settings = configurations[installationId ?? names[0]!]
  if (!settings) throw new ApiError(404,'INSTALLATION_NOT_CONFIGURED','The selected installation is not configured')
  if (settings.operatorSubjects && !settings.operatorSubjects.includes(subject ?? '')) throw new ApiError(403,'INSTALLATION_ACCESS_DENIED','This subject is not an explicitly authorized operator of the selected installation')
  return settings
}

export function productCredentialRequest(targetEndpoint: z.infer<typeof endpoint>, path: string, token: string, method: 'POST' | 'DELETE', body?: unknown): Promise<Record<string, unknown>> {
  const target = new URL(targetEndpoint.url.replace(/\/$/, '') + path)
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body))
  return new Promise((resolve, reject) => {
    const outgoing = request(target, { method, ca: targetEndpoint.caFile ? readFileSync(targetEndpoint.caFile) : undefined, rejectUnauthorized: true, signal: AbortSignal.timeout(10_000), headers: { Authorization: 'Bearer ' + token, ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}) } }, incoming => {
      let size = 0; const chunks: Buffer[] = []
      incoming.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 1024 * 1024) { incoming.destroy(); reject(new ApiError(502, 'PRODUCT_RESPONSE_INVALID', 'Product response exceeded the bounded contract')) } else chunks.push(chunk) })
      incoming.on('error', () => reject(new ApiError(503, 'PRODUCT_OUTCOME_UNKNOWN', 'Product outcome is unknown; retry the exact durable operation')))
      incoming.on('end', () => {
        if (!incoming.statusCode || incoming.statusCode < 200 || incoming.statusCode >= 300) return reject(new ApiError(incoming.statusCode === 410 ? 410 : 503, incoming.statusCode === 410 ? 'PRODUCT_RECEIPT_EXPIRED' : 'PRODUCT_OPERATION_INCOMPLETE', 'Product operation did not return a usable receipt; review durable status before retrying'))
        try { const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); resolve(value as Record<string, unknown>) } catch { reject(new ApiError(502, 'PRODUCT_RESPONSE_INVALID', 'Product receipt did not match its contract')) }
      })
    })
    outgoing.on('error', () => reject(new ApiError(503, 'PRODUCT_OUTCOME_UNKNOWN', 'Product outcome is unknown; retry the exact durable operation')))
    outgoing.end(payload)
  })
}

/** Every remote operation ID is stable across transport errors. Neither token
 * expiration nor a lost response triggers a replacement credential issuance. */
export async function runEnrollment(store: EnrollmentStore, settings: EnrollmentSettings, principal: Principal, actorId: string, action: Action, input?: Policy, operationId?: string) {
  const policy = input ?? JSON.parse(store.get(actorId).requestJson) as Policy
  const permissions = ['hivemem:admin:agents', ...(action === 'disable' ? [] : policy.scopes.map(scope => 'hivemem:' + scope))]
  const tokens = { emberpath: await enrollmentDelegation(principal, 'emberpath', ['router:keys:write']), hivemem: await enrollmentDelegation(principal, 'hivemem', permissions) }
  const run = await enrollmentWrite(() => store.begin(principal.sub, actorId, action, input, operationId))
  if (!run.lease) return enrollmentWrite(() => store.result(run.operation.id))
  const lease = run.lease, id = run.operation.id
  try {
    for (const product of ['iam', 'emberpath', 'hivemem'] as const) {
      const current = store.operation(id), steps = JSON.parse(current.stepsJson) as Record<string, { ok?: boolean }>
      if (steps[product]?.ok) continue
      const enrollment = store.get(actorId), resourceId = ({ iam: enrollment.iamId, emberpath: enrollment.routerKeyId, hivemem: enrollment.memoryId })[product]
      if (action === 'disable' && !resourceId) continue
      const productOperation = enrollmentDigest(settings.installationId + ':' + id + ':' + product)
      await enrollmentWrite(() => store.mark(lease, id, product, 'sent', 0))
      try {
        if (product === 'iam') {
          const rawKey = 'sa_' + nanoid(8) + '.' + nanoid(32)
          const hash = action === 'disable' ? '' : await argon2.hash(rawKey, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 })
          await enrollmentWrite(() => store.localIdentity(lease, id, policy, rawKey, hash))
        } else {
          const deadline = enrollment.credentialExpiresAt ? new Date(enrollment.credentialExpiresAt).toISOString() : new Date(0).toISOString()
          const body = product === 'emberpath' ? { action, actorId, displayName: policy.displayName, workspaceId: policy.workspaceId, expiresAt: deadline, ...(resourceId ? { resourceId } : {}) }
            : { action, agent_id: resourceId ?? actorId, display_name: policy.displayName, description: policy.description, scopes: policy.scopes, workspace_id: policy.workspaceId, expires_at: deadline }
          const result = await productCredentialRequest(settings.products[product], (product === 'emberpath' ? '/client-keys/operations/' : '/actor-credentials/') + productOperation, tokens[product], 'POST', body)
          const returnedId = result[product === 'emberpath' ? 'resourceId' : 'agent_id'], secret = result[product === 'emberpath' ? 'apiKey' : 'token']
          const expectedId = product === 'emberpath' ? resourceId ?? 'actor-key-' + actorId : resourceId ?? actorId
          const returnedOperation = result[product === 'emberpath' ? 'operationId' : 'operation_id']
          if (result.ok !== true || returnedId !== expectedId || returnedOperation !== productOperation || action !== 'disable' && (typeof secret !== 'string' || secret.length < 32 || secret.length > 16384 || product === 'emberpath' && !secret.startsWith('sk-') || product === 'hivemem' && secret.split('.').length !== 3)) throw new ApiError(502, 'PRODUCT_RESPONSE_INVALID', 'Product credential receipt is incomplete or bound to another resource')
          await enrollmentWrite(() => store.complete(lease, id, product, returnedId, typeof secret === 'string' ? secret : undefined))
        }
      } catch (error) {
        await enrollmentWrite(() => store.mark(lease, id, product, 'unknown', error instanceof ApiError ? error.status : 503))
        if (action !== 'disable') break
      }
    }
    await enrollmentWrite(() => store.finish(lease, id))
    return enrollmentWrite(() => store.result(id))
  } finally { await enrollmentWrite(() => store.release(lease)) }
}

export async function acknowledgeEnrollment(store: EnrollmentStore, settings: EnrollmentSettings, principal: Principal, actorId: string, operationId: string) {
  const operation = store.operation(operationId)
  if (operation.actorId !== actorId || operation.ownerId !== principal.sub || operation.status !== 'completed') throw new ApiError(409, 'RECEIPT_CONFLICT', 'Only the owning operator can acknowledge a completed operation')
  if (store.importedOperation(operationId)) { await enrollmentWrite(() => store.acknowledge(principal.sub, operationId)); return }
  const policy = JSON.parse(store.get(actorId).requestJson) as Policy
  const tokens = { emberpath: await enrollmentDelegation(principal, 'emberpath', ['router:keys:write']), hivemem: await enrollmentDelegation(principal, 'hivemem', ['hivemem:admin:agents', ...policy.scopes.map(scope => 'hivemem:' + scope)]) }
  for (const product of ['emberpath', 'hivemem'] as const) await productCredentialRequest(settings.products[product], (product === 'emberpath' ? '/client-keys/operations/' : '/actor-credentials/') + enrollmentDigest(settings.installationId + ':' + operationId + ':' + product) + '/receipt', tokens[product], 'DELETE')
  await enrollmentWrite(() => store.acknowledge(principal.sub, operationId))
}

const stores = new Map<string,EnrollmentStore>()
export function enrollmentStore(selected?: EnrollmentSettings): EnrollmentStore {
  const settings = selected ?? enrollmentSettings()
  if (!settings) throw new ApiError(503, 'ENROLLMENT_UNCONFIGURED', 'This installation has no configured external product enrollment APIs')
  let store = stores.get(settings.installationId)
  if (!store) { store = new EnrollmentStore(new Database(sqlitePathFromUrl(env.DATABASE_URL)), enrollmentCipher(env.COOKIE_SECRET), settings.installationId); stores.set(settings.installationId,store) }
  return store
}
export async function enrollmentWrite<T>(write: () => T): Promise<T> {
  const deadline = Date.now() + 5000
  for (;;) { try { return write() } catch (error) { const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : ''; if (!/^SQLITE_(BUSY|LOCKED)/.test(code)) throw error; if (Date.now() >= deadline) throw new ApiError(503, 'ENROLLMENT_BUSY', 'Enrollment store is busy; retry the same operation'); await new Promise(resolve => setTimeout(resolve, 25)) } }
}
