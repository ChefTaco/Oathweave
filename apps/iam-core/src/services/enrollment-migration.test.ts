import { expect, it } from 'vitest'
import Database from '../db/sqlite.js'
import { readdirSync,readFileSync } from 'node:fs'
import { createCipheriv,randomBytes,scryptSync } from 'node:crypto'
import { enrollmentMigrationSchema,migrateEnrollments } from './enrollment-migration.js'
import { enrollmentCipher } from './enrollment-cipher.js'
import { EnrollmentStore } from './enrollment-store.js'
const sourceSecret='c'.repeat(64),targetSecret='d'.repeat(64)
function cipher(value:string){const iv=randomBytes(12),instance=createCipheriv('aes-256-gcm',scryptSync(sourceSecret,'hive-router-envelope',32),iv),body=Buffer.concat([instance.update(value,'utf8'),instance.final()]);return[iv,instance.getAuthTag(),body].map(part=>part.toString('hex')).join(':')}
function fixture(){
 const source=new Database(':memory:'),target=new Database(':memory:')
 for(const name of readdirSync(new URL('../../prisma/migrations/',import.meta.url)).filter(name=>/^\d/.test(name)).sort())target.exec(readFileSync(new URL(`../../prisma/migrations/${name}/migration.sql`,import.meta.url),'utf8'))
 source.exec(`CREATE TABLE ActorEnrollment(actorId TEXT PRIMARY KEY,ownerId TEXT,installationId TEXT,requestHash TEXT,requestJson TEXT,credentialExpiresAt INTEGER,iamId TEXT,routerKeyId TEXT,memoryId TEXT,encryptedSecrets TEXT,receiptExpiresAt INTEGER,status TEXT,updatedAt INTEGER); CREATE TABLE ActorLifecycleOperation(id TEXT PRIMARY KEY,bindingKey TEXT,actorId TEXT,ownerId TEXT,action TEXT,identifiersJson TEXT,stepsJson TEXT,encryptedSecrets TEXT,receiptExpiresAt INTEGER,status TEXT,createdAt INTEGER,updatedAt INTEGER); CREATE TABLE ActorLifecycleLease(bindingKey TEXT PRIMARY KEY,token TEXT,leaseUntil INTEGER);`)
 target.prepare('INSERT INTO users (id,email,username,displayName,passwordHash,updatedAt) VALUES (?,?,?,?,?,?)').run('reviewed-subject','alice@example.com','reviewed-user','Fixture User','fake-hash',Date.now())
 const policy=JSON.stringify({agentId:'fixture-agent',displayName:'Fixture Agent',iamClientId:'fixture-client',scopes:['memories:read'],expiresHours:24})
 source.prepare('INSERT INTO ActorEnrollment (actorId,ownerId,installationId,requestHash,requestJson,credentialExpiresAt,iamId,routerKeyId,memoryId,encryptedSecrets,receiptExpiresAt,status,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').run('fixture-agent','legacy-owner','legacy-source','a'.repeat(64),policy,Date.now()+3600_000,'preserved-iam','preserved-router','preserved-memory',cipher(JSON.stringify({routerApiKey:'fixture-preserved-router-key'})),Date.now()+300_000,'completed',Date.now())
 source.prepare('INSERT INTO ActorLifecycleOperation (id,bindingKey,actorId,ownerId,action,identifiersJson,stepsJson,encryptedSecrets,receiptExpiresAt,status,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').run('fixture-operation','enrollment:fixture-agent','fixture-agent','legacy-owner','rotate',JSON.stringify({routerClientKeyId:'preserved-router'}),JSON.stringify({router:{ok:true,status:200}}),cipher(JSON.stringify({routerApiKey:'fixture-partial-key'})),Date.now()+300_000,'partial',Date.now(),Date.now())
 const config=enrollmentMigrationSchema.parse({installationId:'fixture-installation',issuer:'https://identity.example.com',sourceDatabase:'/opt/source/snapshot.sqlite',sourceSecretFile:'/opt/source/envelope.key',targetDatabase:'/opt/identity/state.sqlite',targetReceiptSecretFile:'/opt/identity/receipt.key',ownerMappings:[{legacyOwnerId:'legacy-owner',issuer:'https://identity.example.com',subject:'reviewed-subject'}]})
 return{source,target,config}
}
it('requires the exact reviewed snapshot and explicit subject mapping, preserves IDs and expiry, re-encrypts receipts and is idempotent',()=>{
 const {source,target,config}=fixture();try{
 const sourceBefore=source.serialize(),preview=migrateEnrollments(source,target,config,{source:sourceSecret,target:targetSecret})
 expect(preview).toMatchObject({enrollments:1,operations:1,liveReceipts:2,applied:false})
 expect(target.prepare('SELECT count(*) AS n FROM ActorEnrollment').get()).toEqual({n:0})
 expect(()=>migrateEnrollments(source,target,config,{source:sourceSecret,target:targetSecret},true)).toThrow(/digests/)
 const reviewed={...config,reviewedSourceDigest:preview.sourceDigest,reviewedMappingDigest:preview.mappingDigest}
 expect(migrateEnrollments(source,target,reviewed,{source:sourceSecret,target:targetSecret},true).applied).toBe(true)
 expect(source.serialize().equals(sourceBefore)).toBe(true)
 const row=target.prepare('SELECT * FROM ActorEnrollment').get() as Record<string,unknown>
 expect(row).toMatchObject({ownerId:'reviewed-subject',iamId:'preserved-iam',routerKeyId:'preserved-router',memoryId:'preserved-memory'})
 expect(row.receiptExpiresAt).toBe((source.prepare('SELECT receiptExpiresAt FROM ActorEnrollment').get() as Record<string,unknown>).receiptExpiresAt)
 const store=new EnrollmentStore(target,enrollmentCipher(targetSecret),'fixture-installation')
 expect(store.legacyReceipt('reviewed-subject','fixture-agent').secrets.routerApiKey).toBe('fixture-preserved-router-key')
 expect(()=>store.legacyReceipt('legacy-owner','fixture-agent')).toThrow(/does not exist/)
 expect(store.result('fixture-operation').secrets.routerApiKey).toBe('fixture-partial-key')
 expect(store.operation('fixture-operation').status).toBe('migration-review')
 expect(migrateEnrollments(source,target,reviewed,{source:sourceSecret,target:targetSecret},true).repeated).toBe(true)
 expect(()=>migrateEnrollments(source,target,{...reviewed,installationId:'different-installation'},{source:sourceSecret,target:targetSecret},true)).toThrow(/digests/)
 store.acknowledgeLegacyReceipt('reviewed-subject','fixture-agent');expect(()=>store.legacyReceipt('reviewed-subject','fixture-agent')).toThrow(/expired or acknowledged/)
 }finally{source.close();target.close()}
})
it('never infers ownership by email, and rejects another issuer or an active legacy writer',()=>{
 const {source,target,config}=fixture();try{
 expect(()=>migrateEnrollments(source,target,{...config,ownerMappings:[]},{source:sourceSecret,target:targetSecret})).toThrow(/explicit reviewed/)
 expect(()=>migrateEnrollments(source,target,{...config,ownerMappings:[{...config.ownerMappings[0]!,issuer:'https://other.example.com'}]},{source:sourceSecret,target:targetSecret})).toThrow(/different issuer/)
 source.pragma('query_only = OFF');source.prepare('INSERT INTO ActorLifecycleLease VALUES (?,?,?)').run('enrollment:fixture-agent','fixture-lease',Date.now()+120_000)
 expect(()=>migrateEnrollments(source,target,config,{source:sourceSecret,target:targetSecret})).toThrow(/active/)
 }finally{source.close();target.close()}
})
it('imports independent source snapshots into separate namespaces of one authority without merging native identities or public IDs',()=>{
 const first=fixture(),second=fixture();try{
 second.source.prepare('UPDATE ActorEnrollment SET encryptedSecrets = ?').run(cipher(JSON.stringify({routerApiKey:'fixture-second-installation-key'})))
 const one=first.config,two={...second.config,installationId:'second-installation'}
 const previewOne=migrateEnrollments(first.source,first.target,one,{source:sourceSecret,target:targetSecret})
 migrateEnrollments(first.source,first.target,{...one,reviewedSourceDigest:previewOne.sourceDigest,reviewedMappingDigest:previewOne.mappingDigest},{source:sourceSecret,target:targetSecret},true)
 const previewTwo=migrateEnrollments(second.source,first.target,two,{source:sourceSecret,target:targetSecret})
 migrateEnrollments(second.source,first.target,{...two,reviewedSourceDigest:previewTwo.sourceDigest,reviewedMappingDigest:previewTwo.mappingDigest},{source:sourceSecret,target:targetSecret},true)
 expect(first.target.prepare('SELECT count(*) AS n FROM users').get()).toEqual({n:1})
 expect(first.target.prepare('SELECT count(*) AS n FROM service_accounts').get()).toEqual({n:0})
 const a=new EnrollmentStore(first.target,enrollmentCipher(targetSecret),one.installationId),b=new EnrollmentStore(first.target,enrollmentCipher(targetSecret),two.installationId)
 expect(a.list()).toHaveLength(1);expect(b.list()).toHaveLength(1)
 expect(a.get('fixture-agent').routerKeyId).toBe('preserved-router');expect(b.get('fixture-agent').routerKeyId).toBe('preserved-router')
 a.acknowledgeLegacyReceipt('reviewed-subject','fixture-agent')
 expect(b.legacyReceipt('reviewed-subject','fixture-agent').secrets.routerApiKey).toBe('fixture-second-installation-key')
 expect(a.operation('fixture-operation').id).toBe(b.operation('fixture-operation').id)
 }finally{first.source.close();first.target.close();second.source.close();second.target.close()}
})
