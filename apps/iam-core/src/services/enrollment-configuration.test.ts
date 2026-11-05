import { afterEach,expect,it,vi } from 'vitest'
vi.mock('../config/env.js',()=>({env:{DATABASE_URL:'file:/opt/identity/state.sqlite',COOKIE_SECRET:'f'.repeat(64)}}))
vi.mock('../db/client.js',()=>({prisma:{}}))
const {enrollmentConfigurations,enrollmentSettings}=await import('./enrollment-runtime.js')
afterEach(()=>vi.unstubAllEnvs())
const products=(name:string)=>({emberpath:{url:`https://${name}-models.example.com/api`},hivemem:{url:`https://${name}-memory.example.com/v1`}})
function multi(){vi.stubEnv('IAM_BROWSER_ISSUER','https://identity.example.com');vi.stubEnv('IAM_ENROLLMENT_PRODUCTS_JSON','');vi.stubEnv('IAM_ENROLLMENT_INSTALLATION_ID','');vi.stubEnv('IAM_ENROLLMENT_INSTALLATIONS_JSON',JSON.stringify({first:{products:products('first'),operatorSubjects:['fixture-operator']},second:{products:products('second'),operatorSubjects:['other-operator']}}))}
it('requires an exact namespace and an explicit authorized subject, without changing the single-install interface',()=>{
 multi();expect(()=>enrollmentSettings(undefined,'fixture-operator')).toThrow(/exact installation/)
 expect(enrollmentSettings('first','fixture-operator')?.installationId).toBe('first')
 expect(()=>enrollmentSettings('second','fixture-operator')).toThrow(/not an explicitly authorized/)
 expect(()=>enrollmentSettings('missing','fixture-operator')).toThrow(/not configured/)
 vi.stubEnv('IAM_ENROLLMENT_INSTALLATIONS_JSON','');vi.stubEnv('IAM_ENROLLMENT_INSTALLATION_ID','single');vi.stubEnv('IAM_ENROLLMENT_PRODUCTS_JSON',JSON.stringify(products('single')))
 expect(enrollmentSettings()?.installationId).toBe('single')
})
it('rejects mixed legacy and namespace configuration, absent explicit operators, and endpoint aliases across independent installations',()=>{
 multi();vi.stubEnv('IAM_ENROLLMENT_INSTALLATION_ID','legacy');expect(()=>enrollmentConfigurations()).toThrow(/never both/)
 vi.stubEnv('IAM_ENROLLMENT_INSTALLATION_ID','');vi.stubEnv('IAM_ENROLLMENT_INSTALLATIONS_JSON',JSON.stringify({first:{products:products('same'),operatorSubjects:['fixture-operator']},second:{products:products('same'),operatorSubjects:['fixture-operator']}}));expect(()=>enrollmentConfigurations()).toThrow(/must not alias/)
 vi.stubEnv('IAM_ENROLLMENT_INSTALLATIONS_JSON',JSON.stringify({first:{products:products('first')}}));expect(()=>enrollmentConfigurations()).toThrow()
})
