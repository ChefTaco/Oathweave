import Database from 'better-sqlite3'
import { createDecipheriv, scryptSync } from 'node:crypto'
import { z } from 'zod'
import { EnrollmentRequestSchema } from '../schemas/enrollments.js'
import { enrollmentCipher } from './enrollment-cipher.js'
import { enrollmentDigest } from './enrollment-store.js'

export const enrollmentMigrationSchema = z.object({
  installationId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
  issuer: z.url().refine(value => { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash }),
  sourceDatabase: z.string().regex(/^\//), sourceSecretFile: z.string().regex(/^\//),
  targetDatabase: z.string().regex(/^\//), targetReceiptSecretFile: z.string().regex(/^\//),
  ownerMappings: z.array(z.object({ legacyOwnerId: z.string().min(1).max(200), issuer: z.string(), subject: z.string().min(1).max(200) }).strict()).max(1000),
  reviewedSourceDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  reviewedMappingDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
}).strict()
export type EnrollmentMigrationConfig = z.infer<typeof enrollmentMigrationSchema>
interface LegacyEnrollment { actorId: string; ownerId: string; requestHash: string; requestJson: string; credentialExpiresAt: number | string | null; iamId: string | null; routerKeyId: string | null; memoryId: string | null; encryptedSecrets: string | null; receiptExpiresAt: number | string | null; status: string; updatedAt: number | string }
interface LegacyOperation { id: string; bindingKey: string; actorId: string; ownerId: string; action: string; identifiersJson: string; stepsJson: string; encryptedSecrets: string | null; receiptExpiresAt: number | string | null; status: string; createdAt: number | string; updatedAt: number | string }
function timestamp(value: number | string | null): number | null {
  if (value === null) return null
  const result = typeof value === 'number' ? value : Date.parse(value)
  if (!Number.isFinite(result)) throw new Error('Legacy enrollment has an invalid timestamp; preserve it for explicit repair')
  return result
}
function legacyDecrypt(value: string, secret: string): string {
  const parts = value.split(':'); if (parts.length !== 3) throw new Error('Invalid legacy receipt envelope')
  const decipher = createDecipheriv('aes-256-gcm', scryptSync(secret, 'hive-router-envelope', 32), Buffer.from(parts[0]!, 'hex'))
  decipher.setAuthTag(Buffer.from(parts[1]!, 'hex'))
  return Buffer.concat([decipher.update(Buffer.from(parts[2]!, 'hex')), decipher.final()]).toString('utf8')
}

/** Offline, source-preserving adoption. One logical source snapshot and one exact
 * reviewed mapping are bound to one destination installation. No network calls,
 * product account changes, credential rotations or email matching take place. */
export function migrateEnrollments(source: Database.Database, target: Database.Database, config: EnrollmentMigrationConfig, secrets: { source: string; target: string }, apply = false, now = Date.now()) {
  if (source === target) throw new Error('Source and destination must be separate snapshots')
  source.pragma('query_only = ON'); target.pragma('foreign_keys = ON'); target.pragma('busy_timeout = 0')
  if (source.prepare('PRAGMA integrity_check').get() && JSON.stringify(source.prepare('PRAGMA integrity_check').all()) !== '[{"integrity_check":"ok"}]') throw new Error('Source enrollment snapshot failed integrity checking')
  source.exec('BEGIN')
  let enrollments: LegacyEnrollment[], operations: LegacyOperation[], sourceDigest: string
  try {
    if (source.prepare('SELECT 1 FROM ActorLifecycleLease WHERE leaseUntil > ? LIMIT 1').get(now)) throw new Error('Source has active actor operation leases; use a quiesced backup with dispatchers stopped')
    enrollments = source.prepare('SELECT * FROM ActorEnrollment ORDER BY actorId').all() as LegacyEnrollment[]
    operations = source.prepare("SELECT * FROM ActorLifecycleOperation WHERE bindingKey NOT LIKE 'native-credential:%' ORDER BY id").all() as LegacyOperation[]
    sourceDigest = enrollmentDigest(source.serialize().toString('base64'))
  } finally { source.exec('ROLLBACK') }
  const mappings = [...config.ownerMappings].sort((a, b) => a.legacyOwnerId.localeCompare(b.legacyOwnerId)), ownerMap = new Map<string, string>()
  for (const mapping of mappings) {
    if (mapping.issuer !== config.issuer || ownerMap.has(mapping.legacyOwnerId)) throw new Error('Owner mapping is duplicated or references a different issuer')
    if (!target.prepare('SELECT id FROM users WHERE id = ?').get(mapping.subject)) throw new Error('Explicit mapped Oathweave subject does not exist; account IDs are never inferred by email')
    ownerMap.set(mapping.legacyOwnerId, mapping.subject)
  }
  const mappingDigest = enrollmentDigest(JSON.stringify({ installationId: config.installationId, issuer: config.issuer, mappings }))
  for (const row of [...enrollments, ...operations]) if (!ownerMap.has(row.ownerId)) throw new Error('Every legacy receipt owner needs an explicit reviewed issuer/subject mapping')
  const cipher = enrollmentCipher(secrets.target)
  let liveReceipts = 0, historicalReceipts = 0, reviewOnly = 0
  const rewrap = (value: string | null, expiry: number | string | null) => {
    if (!value) return null
    // Re-encrypt even expired evidence; original expiry stays authoritative. It
    // remains recovery evidence, never an API-visible usable credential receipt.
    const plain = legacyDecrypt(value, secrets.source); JSON.parse(plain)
    if ((timestamp(expiry) ?? 0) > now) liveReceipts++; else historicalReceipts++
    return cipher.encrypt(plain)
  }
  const enrollmentRows = enrollments.map(row => {
    const policy = EnrollmentRequestSchema.safeParse(JSON.parse(row.requestJson))
    const identityAvailable = !row.iamId || !!target.prepare('SELECT id FROM service_accounts WHERE id = ?').get(row.iamId)
    const status = row.status === 'contained' ? 'contained' : row.status === 'completed' && policy.success && identityAvailable && timestamp(row.credentialExpiresAt) !== null ? 'completed' : 'migration-review'
    if (status === 'migration-review') reviewOnly++
    return { ...row, ownerId: ownerMap.get(row.ownerId)!, status, encryptedSecrets: rewrap(row.encryptedSecrets, row.receiptExpiresAt) }
  })
  const operationRows = operations.map(row => {
    const oldSteps: unknown = JSON.parse(row.stepsJson)
    if (!oldSteps || typeof oldSteps !== 'object' || Array.isArray(oldSteps)) throw new Error('Legacy lifecycle steps are malformed; retain source evidence for review')
    const status = ['completed','acknowledged','compensated','superseded'].includes(row.status) ? row.status : 'migration-review'
    if (status === 'migration-review') reviewOnly++
    return { ...row, ownerId: ownerMap.get(row.ownerId)!, status, encryptedSecrets: rewrap(row.encryptedSecrets, row.receiptExpiresAt) }
  })
  const summary = { schema: 1, installationId: config.installationId, sourceDigest, mappingDigest, enrollments: enrollments.length, operations: operations.length, liveReceipts, historicalReceipts, reviewOnly, applied: false, repeated: false }
  if (!apply) return summary
  if (sourceDigest !== config.reviewedSourceDigest || mappingDigest !== config.reviewedMappingDigest) throw new Error('Migration review digests do not match this exact source and ownership mapping; run a new dry-run for review')
  return target.transaction(() => {
    const previous = target.prepare('SELECT sourceDigest,reviewDigest FROM EnrollmentMigration WHERE installationId = ?').get(config.installationId) as { sourceDigest: string; reviewDigest: string } | undefined
    if (previous) {
      if (previous.sourceDigest !== sourceDigest || previous.reviewDigest !== mappingDigest) throw new Error('An independent or changed installation migration cannot be combined with this destination')
      return { ...summary, applied: true, repeated: true }
    }
    if (target.prepare('SELECT 1 FROM EnrollmentMigration WHERE sourceDigest = ? AND installationId != ? LIMIT 1').get(sourceDigest,config.installationId)) throw new Error('This exact source snapshot was already assigned to another installation namespace; independent state cannot be aliased')
    if (target.prepare('SELECT 1 FROM ActorEnrollment WHERE installationId = ? LIMIT 1').get(config.installationId) || target.prepare('SELECT 1 FROM ActorLifecycleOperation WHERE installationId = ? LIMIT 1').get(config.installationId)) throw new Error('Selected installation coordination namespace is not empty; independent installation records cannot be combined')
    const insertEnrollment = target.prepare('INSERT INTO ActorEnrollment (actorId,nativeActorId,ownerId,installationId,requestHash,requestJson,credentialExpiresAt,iamId,routerKeyId,memoryId,encryptedSecrets,receiptExpiresAt,leaseUntil,status,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?)')
    for (const row of enrollmentRows) insertEnrollment.run(config.installationId + ':' + row.actorId,row.actorId,row.ownerId,config.installationId,row.requestHash,row.requestJson,timestamp(row.credentialExpiresAt),row.iamId,row.routerKeyId,row.memoryId,row.encryptedSecrets,timestamp(row.receiptExpiresAt),row.status,timestamp(row.updatedAt))
    const insertOperation = target.prepare('INSERT INTO ActorLifecycleOperation (id,operationId,installationId,bindingKey,actorId,ownerId,action,identifiersJson,stepsJson,encryptedSecrets,receiptExpiresAt,status,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    for (const row of operationRows) insertOperation.run(config.installationId + ':' + row.id,row.id,config.installationId,'enrollment:' + config.installationId + ':' + row.actorId,row.actorId,row.ownerId,row.action,row.identifiersJson,row.stepsJson,row.encryptedSecrets,timestamp(row.receiptExpiresAt),row.status,timestamp(row.createdAt),timestamp(row.updatedAt))
    target.prepare('INSERT INTO EnrollmentMigration (installationId,sourceDigest,reviewDigest,importedAt,provenanceJson) VALUES (?,?,?,?,?)').run(config.installationId,sourceDigest,mappingDigest,now,JSON.stringify({ issuer:config.issuer,sourceFormat:'legacy-emberpath-actor-coordinator-v1',reviewOnly,legacyEnrollmentOwners:enrollments.map(row=>({actorId:row.actorId,ownerId:row.ownerId})),legacyOperationOwners:operations.map(row=>({operationId:row.id,ownerId:row.ownerId,bindingKey:row.bindingKey,identifiersJson:row.identifiersJson,stepsJson:row.stepsJson})),instruction:'Retain the source snapshot, original signing/envelope keys and product stores. Imported unknown outcomes cannot replay.' }))
    return { ...summary, applied: true }
  }).immediate()
}
