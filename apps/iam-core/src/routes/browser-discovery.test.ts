import { Hono } from 'hono'
import { beforeEach, expect, it, vi } from 'vitest'
import { errorHandler } from '../middleware/error-handler.js'
import { BrowserOpenIdConfigurationSchema } from '../schemas/discovery.js'
const fixtures = vi.hoisted(() => ({
  env: { JWT_ISSUER:'native-issuer', IAM_BROWSER_ISSUER:'https://identity.example.com', IAM_BROWSER_AUTHORIZATION_URL:'https://identity.example.com/auth/authorize', IAM_BROWSER_API_BASE_URL:'https://identity.example.com/api/oathweave' } as Record<string,string|undefined>,
  client: vi.fn(),
}))
vi.mock('../config/env.js',()=>({env:fixtures.env}))
vi.mock('../db/client.js',()=>({prisma:{client:{findUnique:fixtures.client}}}))
vi.mock('../services/audit-service.js',()=>({logAuditEvent:vi.fn()}))
vi.stubEnv('IAM_BROWSER_CLIENT_POLICIES',JSON.stringify({'hivexui-fixture':{audience:'cindertrace',permissions:['security:read']}}))
const { oauthRouter } = await import('./oauth.js')
const app = new Hono().route('/oauth',oauthRouter).onError(errorHandler)
const url='/oauth/.well-known/openid-configuration'
beforeEach(()=>{
 fixtures.client.mockReset().mockResolvedValue({active:true,clientType:'public'})
 fixtures.env.IAM_BROWSER_ISSUER='https://identity.example.com'
 fixtures.env.IAM_BROWSER_AUTHORIZATION_URL='https://identity.example.com/auth/authorize'
 fixtures.env.IAM_BROWSER_API_BASE_URL='https://identity.example.com/api/oathweave'
})
it('returns the configured browser issuer/interactive portal and ignores all forwarding metadata',async()=>{
 const response=await app.request(url+'?client_id=hivexui-fixture',{headers:{host:'attacker.example.com','x-forwarded-host':'attacker.example.com','x-forwarded-proto':'http',forwarded:'host=attacker.example.com;proto=http',authorization:'Bearer obviously-fake-unused'}})
 expect(response.status).toBe(200);expect(response.headers.get('cache-control')).toBe('no-store');expect(response.headers.has('location')).toBe(false);expect(response.headers.has('set-cookie')).toBe(false)
 const body=BrowserOpenIdConfigurationSchema.parse(await response.json())
 expect(body).toMatchObject({issuer:'https://identity.example.com',authorization_endpoint:'https://identity.example.com/auth/authorize',token_endpoint:'https://identity.example.com/api/oathweave/oauth/token',userinfo_endpoint:'https://identity.example.com/api/oathweave/oauth/userinfo',jwks_uri:'https://identity.example.com/api/oathweave/oauth/jwks',token_endpoint_auth_methods_supported:['none'],grant_types_supported:['authorization_code'],code_challenge_methods_supported:['S256']})
 expect(fixtures.client).toHaveBeenCalledWith({where:{id:'hivexui-fixture'},select:{active:true,clientType:true}})
})
it('rejects ambiguous, empty and unregistered selections without accessing any client',async()=>{
 for(const query of ['client_id=','client_id=hivexui-unknown','client_id=native-client','client_id=hivexui-fixture&client_id=hivexui-fixture']) {
  const response=await app.request(url+'?'+query);expect(response.status).toBe(400);expect(response.headers.get('cache-control')).toBe('no-store')
 }
 expect(fixtures.client).not.toHaveBeenCalled()
})
it('rejects missing, inactive and confidential records even with explicit policy',async()=>{
 for(const client of [null,{active:false,clientType:'public'},{active:true,clientType:'confidential'}]) {fixtures.client.mockResolvedValueOnce(client);expect((await app.request(url+'?client_id=hivexui-fixture')).status).toBe(400)}
})
it('fails closed on missing or invalid configuration with no metadata or redirect',async()=>{
 for(const override of [{IAM_BROWSER_AUTHORIZATION_URL:undefined},{IAM_BROWSER_API_BASE_URL:'https://other.example.com/api'},{IAM_BROWSER_ISSUER:'http://identity.example.com'},{IAM_BROWSER_AUTHORIZATION_URL:'https://user:secret@identity.example.com/auth/authorize'}]) {
  const original={...fixtures.env};Object.assign(fixtures.env,override)
  const response=await app.request(url+'?client_id=hivexui-fixture');expect(response.status).toBe(503);expect(await response.json()).toMatchObject({error:'BROWSER_DISCOVERY_UNCONFIGURED'});expect(response.headers.has('location')).toBe(false);Object.assign(fixtures.env,original)
 }
})
it('retains the original native issuer, paths, grants and caching without client selection',async()=>{
 const response=await app.request(url,{headers:{host:'native.example.com','x-forwarded-proto':'https'}});expect(response.status).toBe(200)
 expect(await response.json()).toMatchObject({issuer:'native-issuer',authorization_endpoint:'https://native.example.com/api/v1/oauth/authorize',token_endpoint:'https://native.example.com/api/v1/oauth/token',grant_types_supported:['authorization_code','refresh_token','client_credentials']})
 expect(response.headers.get('cache-control')).toBe('public, max-age=86400');expect(fixtures.client).not.toHaveBeenCalled()
})
