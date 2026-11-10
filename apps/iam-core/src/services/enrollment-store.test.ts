import { expect, it } from 'vitest'
import Database from '../db/sqlite.js'
import { readdirSync, readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { EnrollmentStore } from './enrollment-store.js'
import { enrollmentCipher } from './enrollment-cipher.js'
import { EnrollmentRequestSchema } from '../schemas/enrollments.js'
const policy = EnrollmentRequestSchema.parse({ agentId: 'fixture-agent', displayName: 'Fixture Agent', iamClientId: 'fixture-client', scopes: ['memories:read'], expiresHours: 1 })
function fixture() {
 const database = new Database(':memory:')
 for (const name of readdirSync(new URL('../../prisma/migrations/', import.meta.url)).filter(name=>/^\d/.test(name)).sort()) database.exec(readFileSync(new URL(`../../prisma/migrations/${name}/migration.sql`, import.meta.url), 'utf8'))
 database.prepare('INSERT INTO clients (id,name,updatedAt) VALUES (?,?,?)').run('fixture-client','Fixture Client',Date.now())
 return database
}
it('fences independent workers and atomically checkpoints the IAM credential with its encrypted receipt', () => {
 const database = fixture(); let now = Date.now(); const cipher = enrollmentCipher('e'.repeat(64));
 try {
  const store = new EnrollmentStore(database,cipher,'fixture-installation',()=>now), run = store.begin('fixture-owner',policy.agentId,'enroll',policy)
  expect(()=>store.begin('fixture-owner',policy.agentId,'enroll',policy)).toThrow(/running/)
  store.localIdentity(run.lease!,run.operation.id,policy,'sa_fakepref.fixture-credential','obviously-fake-argon-hash')
  const id=store.get(policy.agentId).iamId
  expect(database.prepare('SELECT count(*) AS n FROM service_accounts').get()).toEqual({n:1})
  expect(JSON.stringify(database.prepare('SELECT * FROM ActorLifecycleOperation').all())).not.toContain('fixture-credential')
  store.release(run.lease!); now+=1
  const resumed=store.begin('fixture-owner',policy.agentId,'enroll',policy)
  expect(JSON.parse(resumed.operation.stepsJson).iam.ok).toBe(true)
  expect(store.result(run.operation.id).secrets.iamApiKey).toBe('sa_fakepref.fixture-credential')
  expect(store.get(policy.agentId).iamId).toBe(id)
  store.release(resumed.lease!); now+=120_001
  const newer=store.begin('fixture-owner',policy.agentId,'enroll',policy)
  expect(()=>store.mark(resumed.lease!,run.operation.id,'emberpath','sent',0)).toThrow(/lease was lost/)
  store.release(resumed.lease!); expect(()=>store.begin('fixture-owner',policy.agentId,'enroll',policy)).toThrow(/running/)
  store.release(newer.lease!)
 } finally {database.close()}
})
it('does not replay completed steps, extend deadlines, merge another owner, or recover acknowledged credentials',()=>{
 const database=fixture();let now=Date.now();const store=new EnrollmentStore(database,enrollmentCipher('e'.repeat(64)),'fixture-installation',()=>now)
 try{
  const run=store.begin('fixture-owner',policy.agentId,'enroll',policy),deadline=store.get(policy.agentId).credentialExpiresAt
  store.complete(run.lease!,run.operation.id,'iam','fixture-identity','fixture-iam-key')
  const expiry=store.operation(run.operation.id).receiptExpiresAt
  now+=1000;store.complete(run.lease!,run.operation.id,'emberpath','fixture-router','fixture-router-key')
  store.complete(run.lease!,run.operation.id,'hivemem','fixture-agent','fixture-memory-token');store.finish(run.lease!,run.operation.id);store.release(run.lease!)
  expect(store.operation(run.operation.id).receiptExpiresAt).toBe(expiry)
  const replay=store.begin('fixture-owner',policy.agentId,'enroll',policy);expect(replay.lease).toBeNull()
  expect(()=>store.begin('other-owner',policy.agentId,'enroll',policy)).toThrow(/another/)
  expect(()=>store.begin('fixture-owner',policy.agentId,'enroll',{...policy,expiresHours:2})).toThrow(/immutable/)
  expect(store.get(policy.agentId).credentialExpiresAt).toBe(deadline)
  expect(()=>store.acknowledge('other-owner',run.operation.id)).toThrow(/owning/)
  store.acknowledge('fixture-owner',run.operation.id);expect(()=>store.begin('fixture-owner',policy.agentId,'enroll',policy)).toThrow(/expired or acknowledged/)
 }finally{database.close()}
})
it('explicit containment supersedes partial operations and preserves product IDs, ownership and records',()=>{
 const database=fixture(),store=new EnrollmentStore(database,enrollmentCipher('e'.repeat(64)),'fixture-installation')
 try{
  const run=store.begin('fixture-owner',policy.agentId,'enroll',policy)
  store.complete(run.lease!,run.operation.id,'iam','fixture-identity','fixture-secret');store.mark(run.lease!,run.operation.id,'emberpath','unknown',503);store.release(run.lease!)
  expect(()=>store.begin('fixture-owner',policy.agentId,'rotate',undefined,randomUUID())).toThrow(/pending/)
  const contain=store.begin('fixture-owner',policy.agentId,'disable',undefined,randomUUID())
  expect(store.operation(run.operation.id).encryptedSecrets).toBeNull();expect(store.operation(run.operation.id).status).toBe('compensated')
  store.complete(contain.lease!,contain.operation.id,'iam','fixture-identity');store.finish(contain.lease!,contain.operation.id);store.release(contain.lease!)
  expect(store.get(policy.agentId).iamId).toBe('fixture-identity');expect(store.get(policy.agentId).status).toBe('contained')
  expect(()=>store.begin('fixture-owner',policy.agentId,'enroll',policy)).toThrow(/Contained/)
 }finally{database.close()}
})
it('rolls IAM issuance back when receipt encryption fails, without leaving an unrecorded service identity',()=>{
 const database=fixture(),cipher={encrypt(){throw new Error('fixture checkpoint failure')},decrypt:(value:string)=>value},store=new EnrollmentStore(database,cipher,'fixture-installation')
 try{const run=store.begin('fixture-owner',policy.agentId,'enroll',policy);expect(()=>store.localIdentity(run.lease!,run.operation.id,policy,'sa_fakepref.fixture-secret','fake-hash')).toThrow(/checkpoint failure/);expect(database.prepare('SELECT count(*) AS n FROM service_accounts').get()).toEqual({n:0});expect(store.get(policy.agentId).iamId).toBeNull()}finally{database.close()}
})
it('refuses to continue a partially completed issuance after its recovery window expires',()=>{
 const database=fixture();let now=Date.now();const store=new EnrollmentStore(database,enrollmentCipher('e'.repeat(64)),'fixture-installation',()=>now)
 try{const run=store.begin('fixture-owner',policy.agentId,'enroll',policy);store.complete(run.lease!,run.operation.id,'iam','fixture-identity','fixture-secret');store.release(run.lease!);now+=900_001;expect(()=>store.begin('fixture-owner',policy.agentId,'enroll',policy)).toThrow(/partial credential receipt expired/);expect(store.operation(run.operation.id).encryptedSecrets).toBeNull();expect(store.get(policy.agentId).iamId).toBe('fixture-identity')}finally{database.close()}
})
it('keeps identical public actor and operation IDs, leases and acknowledgements separate for independent installation namespaces',()=>{
 const database=fixture(),cipher=enrollmentCipher('e'.repeat(64)),first=new EnrollmentStore(database,cipher,'installation-one'),second=new EnrollmentStore(database,cipher,'installation-two')
 try{
  const a=first.begin('fixture-owner',policy.agentId,'enroll',policy),b=second.begin('fixture-owner',policy.agentId,'enroll',policy)
  expect(a.operation.id).toBe(b.operation.id)
  expect(a.lease?.bindingKey).not.toBe(b.lease?.bindingKey)
  expect(()=>first.complete(b.lease!,a.operation.id,'iam','forbidden','forbidden')).toThrow(/another installation/)
  for(const [store,run,label] of [[first,a,'one'],[second,b,'two']] as const){store.localIdentity(run.lease!,run.operation.id,policy,'sa_fakepref.fixture-'+label,'fake-hash-'+label);store.complete(run.lease!,run.operation.id,'emberpath','router-'+label,'router-key-'+label);store.complete(run.lease!,run.operation.id,'hivemem',policy.agentId,'memory-token-'+label);store.finish(run.lease!,run.operation.id);store.release(run.lease!)}
  expect(first.list()).toHaveLength(1);expect(second.list()).toHaveLength(1)
  expect(first.get(policy.agentId).iamId).not.toBe(second.get(policy.agentId).iamId)
  first.acknowledge('fixture-owner',a.operation.id)
  expect(first.result(a.operation.id).secrets).toEqual({})
  expect(second.result(b.operation.id).secrets.memoryToken).toBe('memory-token-two')
  expect(()=>first.operation('unknown')).toThrow(/not found/)
  expect(database.prepare('SELECT count(*) AS n FROM service_accounts').get()).toEqual({n:2})
 }finally{database.close()}
})

it('uses native Prisma timestamp format and rejects expired legacy numeric and ISO service identities before rotation', () => {
 const database=fixture();let now=Date.now();const store=new EnrollmentStore(database,enrollmentCipher('e'.repeat(64)),'fixture-installation',()=>now)
 try {
  const run=store.begin('fixture-owner',policy.agentId,'enroll',policy)
  store.localIdentity(run.lease!,run.operation.id,policy,'sa_fakepref.fixture-credential','fake-hash')
  const identity=database.prepare('SELECT id,expiresAt,createdAt FROM service_accounts').get() as {id:string;expiresAt:string;createdAt:string}
  expect(identity.expiresAt).toBe(new Date(store.get(policy.agentId).credentialExpiresAt!).toISOString().replace('Z','+00:00'))
  expect(identity.createdAt).toBe(new Date(now).toISOString().replace('Z','+00:00'))
  store.complete(run.lease!,run.operation.id,'emberpath','fixture-router','fixture-key');store.complete(run.lease!,run.operation.id,'hivemem',policy.agentId,'fixture-token');store.finish(run.lease!,run.operation.id);store.release(run.lease!)
  const rotate=store.begin('fixture-owner',policy.agentId,'rotate',undefined,randomUUID())
  for(const expired of [now-1,new Date(now-1).toISOString().replace('Z','+00:00')]) {
    database.prepare('UPDATE service_accounts SET expiresAt=? WHERE id=?').run(expired,identity.id)
    expect(()=>store.localIdentity(rotate.lease!,rotate.operation.id,policy,'sa_fakepref.fixture-rotated','new-fake-hash')).toThrow(/expired/)
    expect(database.prepare('SELECT apiKeyHash FROM service_accounts WHERE id=?').get(identity.id)).toEqual({apiKeyHash:'fake-hash'})
  }
  database.prepare('UPDATE service_accounts SET expiresAt=? WHERE id=?').run(identity.expiresAt,identity.id)
  store.localIdentity(rotate.lease!,rotate.operation.id,policy,'sa_fakepref.fixture-rotated','new-fake-hash')
  expect(database.prepare('SELECT expiresAt FROM service_accounts WHERE id=?').get(identity.id)).toEqual({expiresAt:identity.expiresAt})
 } finally {database.close()}
})
