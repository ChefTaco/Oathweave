import { beforeEach,expect,it,vi } from 'vitest'
import { Hono } from 'hono'
import Database from 'better-sqlite3'
import { readdirSync,readFileSync } from 'node:fs'
import { EnrollmentStore } from '../services/enrollment-store.js'
import { enrollmentCipher } from '../services/enrollment-cipher.js'
import { EnrollmentRequestSchema } from '../schemas/enrollments.js'
import { errorHandler } from '../middleware/error-handler.js'
const mocks=vi.hoisted(()=>({stores:new Map<string,unknown>(),subject:'fixture-operator'}))
vi.mock('../config/env.js',()=>({env:{DATABASE_URL:'file:/opt/identity/state.sqlite',COOKIE_SECRET:'f'.repeat(64)}}))
vi.mock('../db/client.js',()=>({prisma:{}}))
vi.mock('../middleware/auth.js',()=>({authMiddleware:async(c:import('hono').Context,next:()=>Promise<void>)=>{c.set('principal',{sub:mocks.subject,actorType:'USER',roles:[],permissions:['iam:sa:read','iam:sa:write'],sessionId:'fixture-session'});await next()}}))
vi.mock('../middleware/recent-session.js',()=>({requireRecentSession:async(_c:unknown,next:()=>Promise<void>)=>next()}))
vi.mock('../services/enrollment-runtime.js',async original=>({...await original<typeof import('../services/enrollment-runtime.js')>(),enrollmentStore:(settings:{installationId:string})=>mocks.stores.get(settings.installationId)}))
const {enrollmentsRouter}=await import('./enrollments.js')
const app=new Hono().route('/api/v1/enrollments',enrollmentsRouter).onError(errorHandler)
const products=(name:string)=>({emberpath:{url:`https://${name}-models.example.com/api`},hivemem:{url:`https://${name}-memory.example.com/v1`}})
beforeEach(()=>{mocks.subject='fixture-operator';vi.stubEnv('IAM_BROWSER_ISSUER','https://identity.example.com');vi.stubEnv('IAM_ENROLLMENT_INSTALLATION_ID','');vi.stubEnv('IAM_ENROLLMENT_PRODUCTS_JSON','');vi.stubEnv('IAM_ENROLLMENT_INSTALLATIONS_JSON',JSON.stringify({first:{products:products('first'),operatorSubjects:['fixture-operator']},second:{products:products('second'),operatorSubjects:['other-operator']}}))})
it('selects and authorizes namespaces before inventory or secret recovery even when browser controls are bypassed',async()=>{
 const database=new Database(':memory:');try{
 for(const name of readdirSync(new URL('../../prisma/migrations/',import.meta.url)).filter(name=>/^\d/.test(name)).sort())database.exec(readFileSync(new URL(`../../prisma/migrations/${name}/migration.sql`,import.meta.url),'utf8'))
 const policy=EnrollmentRequestSchema.parse({agentId:'fixture-agent',displayName:'Fixture',iamClientId:'fixture-client',scopes:['memories:read']})
 for(const name of ['first','second']){const store=new EnrollmentStore(database,enrollmentCipher('f'.repeat(64)),name);mocks.stores.set(name,store);const run=store.begin(name==='first'?'fixture-operator':'other-operator',policy.agentId,'enroll',policy);store.complete(run.lease!,run.operation.id,'iam','identity-'+name,'secret-'+name);store.release(run.lease!)}
 expect((await app.request('/api/v1/enrollments')).status).toBe(400)
 expect((await app.request('/api/v1/enrollments?installationId=second')).status).toBe(403)
 expect((await app.request('/api/v1/enrollments?installationId=unknown')).status).toBe(404)
 const visible=await app.request('/api/v1/enrollments?installationId=first');expect(visible.status).toBe(200);expect(visible.headers.get('cache-control')).toBe('no-store')
 const inventory=await visible.json();expect(inventory.installationId).toBe('first');expect(inventory.data[0].identifiers.iamServiceAccountId).toBe('identity-first');expect(JSON.stringify(inventory)).not.toContain('secret-first')
 expect(await(await app.request('/api/v1/enrollments/installations')).json()).toEqual({installations:['first']})
 const operationId=encodeURIComponent(inventory.data[0].latestOperation.id)
 expect((await app.request(`/api/v1/enrollments/fixture-agent/operations/${operationId}?installationId=second`)).status).toBe(403)
 const owned=await app.request(`/api/v1/enrollments/fixture-agent/operations/${operationId}?installationId=first`);expect(owned.status).toBe(200);expect((await owned.json()).secrets.iamApiKey).toBe('secret-first')
 mocks.subject='other-operator';expect((await app.request(`/api/v1/enrollments/fixture-agent/operations/${operationId}?installationId=first`)).status).toBe(403)
 }finally{database.close();mocks.stores.clear();vi.unstubAllEnvs()}
})
