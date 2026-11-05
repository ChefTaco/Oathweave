import { beforeEach, expect, it, vi } from 'vitest'
import { generateKeyPair, exportJWK, jwtVerify, SignJWT } from 'jose'
import { Hono } from 'hono'
const mocks = vi.hoisted(() => ({ session: vi.fn(), keys: {} as { privateKey?: CryptoKey; publicKey?: CryptoKey; jwks?: unknown } }))
vi.mock('../db/client.js', () => ({ prisma: { session: { findFirst: mocks.session } } }))
vi.mock('../config/env.js', () => ({ env: { JWT_ISSUER: 'native-identity', JWT_ACCESS_TTL: 3600 } }))
vi.mock('../utils/keys.js', () => ({ getPrivateKey: async () => mocks.keys.privateKey, getSigningKeyId: async () => 'fixture-signing', getPublishedSigningJwks: async () => mocks.keys.jwks }))
const { enrollmentDelegation } = await import('./enrollment-delegation.js')
const { verifyAccessToken } = await import('./token-service.js')
const { authMiddleware } = await import('../middleware/auth.js')
const pair = await generateKeyPair('RS256'); mocks.keys.privateKey = pair.privateKey; mocks.keys.publicKey = pair.publicKey; mocks.keys.jwks = { keys: [{ ...await exportJWK(pair.publicKey), kid: 'fixture-signing' }] }
const principal = { sub: 'fixture-subject', actorType: 'USER' as const, sessionId: 'fixture-session', clientId: 'hivexui-oathweave', roles: [], permissions: ['iam:sa:write'], email: undefined, username: undefined }
beforeEach(() => {
 vi.stubEnv('IAM_BROWSER_ISSUER','https://identity.example.com');vi.stubEnv('IAM_ENROLLMENT_PRODUCTS_JSON','{}')
 mocks.session.mockResolvedValue({ id:'fixture-session',createdAt:new Date(),stepUpVerifiedAt:null,user:{roles:[{role:{name:'Fixture Role',permissions:JSON.stringify(['router:keys:write','hivemem:admin:all'])}}],groupMemberships:[]} })
})
it('uses a dedicated server identity with exact audience, a 60-second lifetime and downscoped current grants',async()=>{
 const token = await enrollmentDelegation(principal,'hivemem',['hivemem:admin:agents','hivemem:memories:read'])
 const {payload}=await jwtVerify(token,pair.publicKey,{issuer:'https://identity.example.com',audience:'hivemem'})
 expect(payload).toMatchObject({sub:principal.sub,clientId:'oathweave-enrollment',actorType:'USER',sessionId:principal.sessionId,roles:[],permissions:['hivemem:admin:agents','hivemem:memories:read']})
 expect(Number(payload.exp)-Number(payload.iat)).toBe(60)
 expect(await verifyAccessToken(token)).toMatchObject({clientId:'oathweave-enrollment'})
 expect(payload.permissions).not.toContain('hivemem:admin:all')
 await expect(enrollmentDelegation(principal,'emberpath',['router:keys:write','router:providers:write'])).rejects.toThrow(/operator/)
 await expect(enrollmentDelegation(principal,'hivemem',['hivemem:admin:all'])).rejects.toThrow(/operator/)
})
it('cannot authorize IAM mutations or authenticate service identities, and session revocation is checked again by receiving APIs',async()=>{
 const token=await enrollmentDelegation(principal,'emberpath',['router:keys:write'])
 const app=new Hono().use('*',authMiddleware).get('/api/v1/users',c=>c.json({ok:true})).get('/api/v1/oauth/userinfo',c=>c.json({sub:c.get('principal').sub}))
 expect((await app.request('/api/v1/users',{headers:{Authorization:'Bearer '+token}})).status).toBe(401)
 expect((await app.request('/api/v1/oauth/userinfo',{headers:{Authorization:'Bearer '+token}})).status).toBe(200)
 await expect(enrollmentDelegation({...principal,actorType:'SERVICE_ACCOUNT'},'emberpath',['router:keys:write'])).rejects.toThrow(/interactive/)
 mocks.session.mockResolvedValue(null)
 await expect(verifyAccessToken(token)).rejects.toThrow(/inactive or revoked/)
 await expect(enrollmentDelegation(principal,'emberpath',['router:keys:write'])).rejects.toThrow(/inactive/)
})
it('rejects wrong delegation audiences, missing binding claims and excess token lifetime even with a trusted signing key',async()=>{
 const now=Math.floor(Date.now()/1000)
 for(const mutation of [{aud:'oathweave'},{actorType:'SERVICE_ACCOUNT'},{sessionId:undefined},{delegationVersion:undefined},{exp:now+61}]){
 const token=await new SignJWT({actorType:'USER',clientId:'oathweave-enrollment',delegationVersion:1,sessionId:'fixture-session',roles:[],permissions:['router:keys:write'],aud:'emberpath',exp:now+60,...mutation}).setProtectedHeader({alg:'RS256',kid:'fixture-signing'}).setSubject('fixture-subject').setIssuer('https://identity.example.com').setIssuedAt(now).setJti('fixture-token').sign(pair.privateKey)
 await expect(verifyAccessToken(token)).rejects.toThrow(/delegation/)
 }
})
