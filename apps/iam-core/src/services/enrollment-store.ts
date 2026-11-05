import { createHash, randomUUID } from 'node:crypto'
import Database from 'better-sqlite3'
import { nanoid } from 'nanoid'
import type { z } from 'zod'
import type { EnrollmentRequestSchema } from '../schemas/enrollments.js'
import { ApiError } from '../types/index.js'
import { enrollmentCipher } from './enrollment-cipher.js'

export type Policy = z.infer<typeof EnrollmentRequestSchema>
export type Action = 'enroll' | 'rotate' | 'disable'
export interface Enrollment { actorId: string; ownerId: string; installationId: string; requestHash: string; requestJson: string; credentialExpiresAt: number | null; iamId: string | null; routerKeyId: string | null; memoryId: string | null; status: string; encryptedSecrets: string | null; receiptExpiresAt: number | null }
export interface Step { service: string; state: 'sent' | 'completed' | 'unknown'; status: number; ok: boolean }
export interface Operation { id: string; bindingKey: string; actorId: string; ownerId: string; action: Action; identifiersJson: string; stepsJson: string; encryptedSecrets: string | null; receiptExpiresAt: number | null; status: string }
export interface Lease { bindingKey: string; token: string }
export const enrollmentDigest = (input: string): string => createHash('sha256').update(input).digest('hex')
const keys = { iam: 'iamId', emberpath: 'routerKeyId', hivemem: 'memoryId' } as const
const secretNames = { iam: 'iamApiKey', emberpath: 'routerApiKey', hivemem: 'memoryToken' } as const
export type EnrollmentProduct = keyof typeof keys
function visibleReceipt(value: string): Record<string, string> {
  const parsed: unknown = JSON.parse(value)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.values(parsed).some(item => item !== null && typeof item !== 'string')) throw new Error('Enrollment receipt does not contain credential strings')
  return Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string,string] => typeof entry[1] === 'string'))
}

/** A lease fences every checkpoint. No database transaction is held over HTTP. */
export class EnrollmentStore {
  constructor(readonly database: Database.Database, private readonly cipher: ReturnType<typeof enrollmentCipher>, readonly installationId: string, private readonly now: () => number = Date.now) { database.pragma('busy_timeout = 0'); database.pragma('foreign_keys = ON') }
  private key(value: string): string { return this.installationId + ':' + value }
  private readonly enrollmentColumns = 'nativeActorId AS actorId,ownerId,installationId,requestHash,requestJson,credentialExpiresAt,iamId,routerKeyId,memoryId,status,encryptedSecrets,receiptExpiresAt'
  private readonly operationColumns = 'operationId AS id,bindingKey,actorId,ownerId,action,identifiersJson,stepsJson,encryptedSecrets,receiptExpiresAt,status'
  private transaction<T>(fn: () => T): T { return this.database.transaction(fn).immediate() }
  get(actorId: string): Enrollment {
    const row = this.database.prepare('SELECT ' + this.enrollmentColumns + ' FROM ActorEnrollment WHERE actorId = ?').get(this.key(actorId)) as Enrollment | undefined
    if (!row || row.installationId !== this.installationId) throw new ApiError(404, 'NOT_FOUND', 'Enrollment not found in this installation')
    return row
  }
  list(): Enrollment[] { return this.database.prepare('SELECT ' + this.enrollmentColumns + ' FROM ActorEnrollment WHERE installationId = ? ORDER BY nativeActorId').all(this.installationId) as Enrollment[] }
  latest(actorId: string): Pick<Operation,'id'|'action'|'status'> | null { return this.database.prepare('SELECT operationId AS id,action,status FROM ActorLifecycleOperation WHERE actorId = ? AND installationId = ? ORDER BY createdAt DESC LIMIT 1').get(actorId, this.installationId) as Pick<Operation,'id'|'action'|'status'> | undefined ?? null }
  operation(id: string): Operation { const row = this.database.prepare('SELECT ' + this.operationColumns + ' FROM ActorLifecycleOperation WHERE id = ?').get(this.key(id)) as Operation | undefined; if (!row) throw new ApiError(404, 'NOT_FOUND', 'Operation not found'); return row }
  private expire(): void {
    for (const table of ['ActorEnrollment', 'ActorLifecycleOperation']) this.database.prepare(`UPDATE ${table} SET encryptedSecrets = NULL, receiptExpiresAt = NULL WHERE receiptExpiresAt <= ? AND installationId = ?`).run(this.now(), this.installationId)
  }
  begin(owner: string, actorId: string, action: Action, input?: Policy, operationId?: string): { enrollment: Enrollment; operation: Operation; lease: Lease | null } {
    this.expire()
    return this.transaction(() => {
      if (action === 'enroll') {
        if (!input || input.agentId !== actorId) throw new ApiError(400, 'INVALID_POLICY', 'An explicit enrollment policy is required')
        const requestJson = JSON.stringify(input), digest = enrollmentDigest(requestJson)
        this.database.prepare('INSERT INTO ActorEnrollment (actorId,nativeActorId,ownerId,installationId,requestHash,requestJson,credentialExpiresAt,status,updatedAt) VALUES (?,?,?,?,?,?,?,\'pending\',?) ON CONFLICT(actorId) DO NOTHING').run(this.key(actorId), actorId, owner, this.installationId, digest, requestJson, this.now() + input.expiresHours * 3600_000, this.now())
        operationId = 'enroll:' + enrollmentDigest(actorId + ':' + digest)
      }
      const enrollment = this.get(actorId)
      if (enrollment.ownerId !== owner || input && enrollment.requestHash !== enrollmentDigest(JSON.stringify(input))) throw new ApiError(409, 'ENROLLMENT_CONFLICT', 'Actor belongs to another operator or immutable policy')
      if (!operationId) throw new ApiError(400, 'OPERATION_REQUIRED', 'Use an explicit operation ID')
      if (action !== 'disable' && (enrollment.status === 'contained' || !enrollment.credentialExpiresAt || enrollment.credentialExpiresAt <= this.now())) throw new ApiError(409, 'ENROLLMENT_EXPIRED', 'Contained or expired enrollments cannot issue credentials')
      const existing = this.database.prepare('SELECT ' + this.operationColumns + ' FROM ActorLifecycleOperation WHERE id = ?').get(this.key(operationId)) as Operation | undefined
      const bindingKey = 'enrollment:' + this.key(actorId)
      if (action === 'enroll' && enrollment.status === 'completed' && !existing) throw new ApiError(409, 'ALREADY_ENROLLED', 'This migrated identity already exists; recover its original receipt or review an explicit rotation without recreating product accounts')
      if (existing && (existing.bindingKey !== bindingKey || existing.ownerId !== owner || existing.action !== action)) throw new ApiError(409, 'OPERATION_CONFLICT', 'Operation belongs to another actor, owner or action')
      if (existing && ['completed', 'acknowledged'].includes(existing.status)) {
        if (action !== 'disable' && !existing.encryptedSecrets) throw new ApiError(410, 'RECEIPT_UNAVAILABLE', 'Receipt expired or acknowledged; review a new explicit rotation if credentials were lost')
        return { enrollment, operation: existing, lease: null }
      }
      if (existing && action !== 'disable' && !existing.encryptedSecrets && Object.values(JSON.parse(existing.stepsJson) as Record<string, Step>).some(step => step.ok)) throw new ApiError(410, 'PARTIAL_RECEIPT_UNAVAILABLE', 'A partial credential receipt expired; review completed resources or explicitly contain them before issuing more credentials')
      if (existing && ['compensated', 'superseded', 'migration-review'].includes(existing.status)) throw new ApiError(409, 'REVIEW_REQUIRED', 'A contained or legacy unknown-outcome operation cannot replay; inspect the migration receipt')
      if (enrollment.status === 'migration-review' && action !== 'disable') throw new ApiError(409, 'MIGRATION_REVIEW_REQUIRED', 'Imported partial enrollment needs explicit product reconciliation before issuance; Disable can contain its recorded resources')
      const held = this.database.prepare('SELECT leaseUntil FROM ActorLifecycleLease WHERE bindingKey = ?').get(bindingKey) as { leaseUntil: number } | undefined
      if (held && held.leaseUntil > this.now()) throw new ApiError(409, 'OPERATION_RUNNING', 'An operation is running; retry its operation ID after its lease ends')
      const pending = this.database.prepare("SELECT id FROM ActorLifecycleOperation WHERE bindingKey = ? AND id != ? AND status IN ('pending','partial','migration-review')").all(bindingKey, this.key(operationId)) as Array<{ id: string }>
      if (pending.length && action !== 'disable') throw new ApiError(409, 'OPERATION_PENDING', 'Resume the pending operation or explicitly contain it with Disable')
      const lease = { bindingKey, token: randomUUID() }
      this.database.prepare('INSERT INTO ActorLifecycleLease VALUES (?,?,?) ON CONFLICT(bindingKey) DO UPDATE SET token = excluded.token, leaseUntil = excluded.leaseUntil').run(bindingKey, lease.token, this.now() + 120_000)
      if (!existing) {
        if (action !== 'enroll') this.database.prepare("UPDATE ActorLifecycleOperation SET encryptedSecrets = NULL, receiptExpiresAt = NULL, status = CASE WHEN status IN ('pending','partial','migration-review') THEN 'compensated' ELSE 'superseded' END WHERE bindingKey = ?").run(bindingKey)
        if (action !== 'enroll') this.database.prepare('UPDATE ActorEnrollment SET encryptedSecrets = NULL, receiptExpiresAt = NULL WHERE actorId = ?').run(this.key(actorId))
        this.database.prepare('INSERT INTO ActorLifecycleOperation (id,operationId,installationId,bindingKey,actorId,ownerId,action,identifiersJson,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?)').run(this.key(operationId), operationId, this.installationId, bindingKey, actorId, owner, action, JSON.stringify({ iamServiceAccountId: enrollment.iamId, routerClientKeyId: enrollment.routerKeyId, memoryAgentId: enrollment.memoryId }), this.now(), this.now())
        if (action === 'disable') this.database.prepare("UPDATE ActorEnrollment SET status = 'contained', encryptedSecrets = NULL, receiptExpiresAt = NULL WHERE actorId = ?").run(this.key(actorId))
      }
      return { enrollment: this.get(actorId), operation: this.operation(operationId), lease }
    })
  }
  private fence(lease: Lease): void {
    if (!lease.bindingKey.startsWith('enrollment:' + this.installationId + ':')) throw new ApiError(409, 'FOREIGN_INSTALLATION_LEASE', 'A lease cannot authorize another installation namespace')
    if (!this.database.prepare('UPDATE ActorLifecycleLease SET leaseUntil = ? WHERE bindingKey = ? AND token = ? AND leaseUntil > ?').run(this.now() + 120_000, lease.bindingKey, lease.token, this.now()).changes) throw new ApiError(409, 'LEASE_LOST', 'Actor operation lease was lost; reload its durable status')
  }
  release(lease: Lease): void { if (!lease.bindingKey.startsWith('enrollment:' + this.installationId + ':')) throw new ApiError(409, 'FOREIGN_INSTALLATION_LEASE', 'A lease cannot release another installation namespace'); this.database.prepare('DELETE FROM ActorLifecycleLease WHERE bindingKey = ? AND token = ?').run(lease.bindingKey, lease.token) }
  mark(lease: Lease, operationId: string, product: EnrollmentProduct, state: Step['state'], status: number): void {
    this.transaction(() => { this.fence(lease); const row = this.operation(operationId), steps = JSON.parse(row.stepsJson) as Record<string, Step>; steps[product] = { service: product, state, status, ok: state === 'completed' }; this.database.prepare('UPDATE ActorLifecycleOperation SET stepsJson = ?, status = ?, updatedAt = ? WHERE id = ?').run(JSON.stringify(steps), 'partial', this.now(), this.key(operationId)) })
  }
  complete(lease: Lease, operationId: string, product: EnrollmentProduct, resourceId: string, secret?: string): void {
    this.transaction(() => {
      this.fence(lease)
      const row = this.operation(operationId), steps = JSON.parse(row.stepsJson) as Record<string, Step>, identifiers = JSON.parse(row.identifiersJson) as Record<string, string>
      const secrets = row.encryptedSecrets ? JSON.parse(this.cipher.decrypt(row.encryptedSecrets)) as Record<string, string> : {}
      if (secret) secrets[secretNames[product]] = secret
      identifiers[{ iam: 'iamServiceAccountId', emberpath: 'routerClientKeyId', hivemem: 'memoryAgentId' }[product]] = resourceId
      steps[product] = { service: product, state: 'completed', status: 200, ok: true }
      const expiry = Object.keys(secrets).length ? Math.min(row.receiptExpiresAt ?? this.now() + 900_000, this.get(row.actorId).credentialExpiresAt ?? this.now() + 900_000) : null
      if (secret && expiry !== null && expiry <= this.now()) throw new ApiError(410, 'RECEIPT_EXPIRED', 'The operation recovery window expired; contain or explicitly rotate after reviewing completed resources')
      this.database.prepare('UPDATE ActorLifecycleOperation SET stepsJson = ?, identifiersJson = ?, encryptedSecrets = ?, receiptExpiresAt = ?, updatedAt = ? WHERE id = ?').run(JSON.stringify(steps), JSON.stringify(identifiers), Object.keys(secrets).length ? this.cipher.encrypt(JSON.stringify(secrets)) : null, expiry, this.now(), this.key(operationId))
      this.database.prepare(`UPDATE ActorEnrollment SET ${keys[product]} = ?, updatedAt = ? WHERE actorId = ?`).run(resourceId, this.now(), this.key(row.actorId))
    })
  }
  /** IAM key mutation and checkpoint share the same SQLite transaction. The slow
   * Argon2 hash is prepared before this method, outside the writer transaction. */
  localIdentity(lease: Lease, operationId: string, policy: Policy, rawKey: string, hash: string): void {
    this.transaction(() => {
      this.fence(lease)
      const row = this.operation(operationId), enrollment = this.get(row.actorId)
      const id = enrollment.iamId ?? nanoid()
      if (row.action === 'enroll') {
        if (!this.database.prepare('SELECT id FROM clients WHERE id = ? AND active = 1').get(policy.iamClientId)) throw new ApiError(400, 'INVALID_CLIENT', 'Enrollment client is missing or disabled')
        this.database.prepare('INSERT INTO service_accounts (id,name,description,clientId,apiKeyHash,apiKeyPrefix,active,allowedIps,expiresAt,createdBy,createdAt,updatedAt) VALUES (?,?,?,?,?,?,1,?,?,?,?,?)').run(id, 'actor:' + this.installationId + ':' + policy.agentId, policy.description, policy.iamClientId, hash, rawKey.slice(3).split('.')[0]!, JSON.stringify(policy.allowedIps), enrollment.credentialExpiresAt === null ? null : new Date(enrollment.credentialExpiresAt).toISOString().replace('Z', '+00:00'), row.ownerId, new Date(this.now()).toISOString().replace('Z', '+00:00'), new Date(this.now()).toISOString().replace('Z', '+00:00'))
        for (const roleId of policy.roleIds) this.database.prepare('INSERT INTO service_account_role_assignments (serviceAccountId,roleId,grantedAt) VALUES (?,?,?)').run(id, roleId, new Date(this.now()).toISOString().replace('Z', '+00:00'))
      } else {
        const existing = this.database.prepare('SELECT active,expiresAt FROM service_accounts WHERE id = ?').get(id) as { active: number; expiresAt: number | string | null } | undefined
        if (row.action !== 'disable' && (!existing?.active || existing.expiresAt !== null && (typeof existing.expiresAt === 'number' ? existing.expiresAt : Date.parse(existing.expiresAt)) <= this.now())) throw new ApiError(409, 'IDENTITY_UNAVAILABLE', 'The existing service identity is missing, disabled or expired')
        const result = row.action === 'disable'
          ? this.database.prepare('UPDATE service_accounts SET active = 0, updatedAt = ? WHERE id = ?').run(new Date(this.now()).toISOString().replace('Z', '+00:00'), id)
          : this.database.prepare('UPDATE service_accounts SET apiKeyHash = ?, apiKeyPrefix = ?, updatedAt = ? WHERE id = ? AND active = 1').run(hash, rawKey.slice(3).split('.')[0]!, new Date(this.now()).toISOString().replace('Z', '+00:00'), id)
        if (!result.changes) throw new ApiError(409, 'IDENTITY_UNAVAILABLE', 'The existing service identity is missing, disabled or expired')
      }
      // complete() also takes a transaction; better-sqlite3 nests with savepoints.
      this.complete(lease, operationId, 'iam', id, row.action === 'disable' ? undefined : rawKey)
    })
  }
  finish(lease: Lease, operationId: string): void {
    this.transaction(() => { this.fence(lease); const row = this.operation(operationId), steps = JSON.parse(row.stepsJson) as Record<string, Step>; const required = row.action === 'disable' ? Object.entries(JSON.parse(row.identifiersJson) as Record<string, string | null>).filter(([, id]) => id).map(([key]) => ({ iamServiceAccountId: 'iam', routerClientKeyId: 'emberpath', memoryAgentId: 'hivemem' })[key]) : ['iam', 'emberpath', 'hivemem']; const done = required.every(product => product && steps[product]?.ok); this.database.prepare('UPDATE ActorLifecycleOperation SET status = ?, updatedAt = ? WHERE id = ?').run(done ? 'completed' : 'partial', this.now(), this.key(operationId)); if (done) this.database.prepare('UPDATE ActorEnrollment SET status = ?, updatedAt = ? WHERE actorId = ?').run(row.action === 'disable' ? 'contained' : 'completed', this.now(), this.key(row.actorId)) })
  }
  result(operationId: string) {
    this.expire()
    const row = this.operation(operationId), ok = ['completed', 'acknowledged'].includes(row.status)
    const steps = Object.entries(JSON.parse(row.stepsJson) as Record<string, Partial<Step>>).map(([key, step]): Step => ({ service: typeof step.service === 'string' ? step.service : key, state: step.state ?? (step.ok ? 'completed' : 'unknown'), status: step.status ?? 0, ok: step.ok === true }))
    return { ok, actorId: row.actorId, action: row.action, operationId: row.id, identifiers: JSON.parse(row.identifiersJson) as Record<string, string | null>, secrets: row.encryptedSecrets ? visibleReceipt(this.cipher.decrypt(row.encryptedSecrets)) : {}, steps, receiptExpiresAt: row.receiptExpiresAt ? new Date(row.receiptExpiresAt).toISOString() : null, remediation: ok ? null : 'Retry the same operation ID and unchanged policy. Product-owned receipts replay exact issuance; unavailable or expired receipts require explicit review or containment.' }
  }
  acknowledge(owner: string, operationId: string): void {
    if (!this.database.prepare("UPDATE ActorLifecycleOperation SET encryptedSecrets = NULL, receiptExpiresAt = NULL, status = 'acknowledged' WHERE id = ? AND ownerId = ? AND status = 'completed'").run(this.key(operationId), owner).changes) throw new ApiError(409, 'RECEIPT_CONFLICT', 'Only the owning operator can acknowledge a completed operation')
  }
  legacyReceipt(owner: string, actorId: string): { actorId: string; secrets: Record<string, string>; receiptExpiresAt: string } {
    const row = this.database.prepare('SELECT ownerId,encryptedSecrets,receiptExpiresAt FROM ActorEnrollment WHERE actorId = ? AND installationId = ?').get(this.key(actorId), this.installationId) as { ownerId: string; encryptedSecrets: string | null; receiptExpiresAt: number | null } | undefined
    if (!row || row.ownerId !== owner) throw new ApiError(404, 'NOT_FOUND', 'Owned recovery receipt does not exist')
    if (!row.encryptedSecrets || !row.receiptExpiresAt || row.receiptExpiresAt <= this.now()) throw new ApiError(410, 'RECEIPT_UNAVAILABLE', 'Legacy recovery receipt expired or acknowledged; source recovery evidence remains separate')
    return { actorId, secrets: visibleReceipt(this.cipher.decrypt(row.encryptedSecrets)), receiptExpiresAt: new Date(row.receiptExpiresAt).toISOString() }
  }
  acknowledgeLegacyReceipt(owner: string, actorId: string): void {
    if (!this.database.prepare('UPDATE ActorEnrollment SET encryptedSecrets = NULL, receiptExpiresAt = NULL WHERE actorId = ? AND installationId = ? AND ownerId = ?').run(this.key(actorId), this.installationId, owner).changes) throw new ApiError(404, 'NOT_FOUND', 'Owned recovery receipt does not exist')
  }
  importedOperation(operationId: string): boolean {
    const row = this.database.prepare('SELECT provenanceJson FROM EnrollmentMigration WHERE installationId = ?').get(this.installationId) as { provenanceJson: string } | undefined
    if (!row) return false
    const provenance = JSON.parse(row.provenanceJson) as { legacyOperationOwners?: Array<{ operationId: string }> }
    return provenance.legacyOperationOwners?.some(item => item.operationId === operationId) ?? false
  }
}
