import {describe,it,expect} from 'vitest'
import {CreateIamClientRequestSchema,IamAssignRolesRequestSchema,EnrollmentRequestSchema,IamUserSchema,IamClientMutationResponseSchema,UpdateIamPasswordPolicyRequestSchema} from './browser-contracts.js'
describe('owned browser identity contracts',()=>{
 it('retains actual request refinements and prevents public-client secret-flow confusion',()=>{
  expect(()=>CreateIamClientRequestSchema.parse({name:'fixture-client'})).toThrow()
  expect(()=>CreateIamClientRequestSchema.parse({name:'fixture-client',clientType:'public',grantTypes:['client_credentials']})).toThrow()
  expect(CreateIamClientRequestSchema.parse({name:'fixture-client',clientType:'public'}).clientType).toBe('public')
  expect(()=>IamAssignRolesRequestSchema.parse({roleIds:[]})).toThrow()
  expect(()=>UpdateIamPasswordPolicyRequestSchema.parse({minLength:1})).toThrow()
 })
 it('preserves enrollment limits beyond the OpenAPI representation',()=>{
  const input={agentId:'fixture-agent',displayName:'Fixture agent',iamClientId:'fixture-client',scopes:['memories:read']}
  expect(EnrollmentRequestSchema.parse(input).workspaceId).toBe('default')
  expect(()=>EnrollmentRequestSchema.parse({...input,scopes:['admin:agents']})).toThrow()
  expect(()=>EnrollmentRequestSchema.parse({...input,roleIds:Array(31).fill('fixture-role')})).toThrow()
 })
 it('keeps browser DTOs independent of persistence secrets and native mutation serialization',()=>{
  const user={id:'fixture',email:'alice@example.com',username:'alice',displayName:null,active:true,lastLoginAt:null,createdAt:'2026-01-01T00:00:00Z',roles:[],passwordHash:'obviously-fake-private-hash'}
  expect(IamUserSchema.parse(user)).not.toHaveProperty('passwordHash')
  expect(()=>IamUserSchema.parse({...user,active:'yes'})).toThrow()
  expect(IamClientMutationResponseSchema.parse({client:{id:'fixture',name:'fixture-client',description:null,active:true,clientType:'public',firstParty:false,redirectUris:'[]',grantTypes:'[]'}}).client.redirectUris).toBe('[]')
 })
})
