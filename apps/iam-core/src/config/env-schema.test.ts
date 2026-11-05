import { describe, expect, it } from 'vitest'
import { validateEnv } from './env-schema.js'

const valid = {
  DATABASE_URL: 'file:/tmp/iam.db',
  JWT_PRIVATE_KEY_PATH: '/tmp/private.pem',
  JWT_PUBLIC_KEY_PATH: '/tmp/public.pem',
  COOKIE_SECRET: 'c'.repeat(32),
  IAM_AGENT_SECRET: 'a'.repeat(16),
}

describe('environment validation', () => {
  it('accepts a minimal configuration and keeps the systemd defaults', () => {
    const result = validateEnv(valid)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.env.PORT).toBe(4200)
      expect(result.env.HOST).toBe('0.0.0.0')
    }
  })

  it('reports one actionable line per variable without echoing values', () => {
    const secret = 'short-secret-value'
    const result = validateEnv({ ...valid, COOKIE_SECRET: secret, IAM_AGENT_SECRET: undefined, PORT: 'eighty' })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.errors).toHaveLength(3)
    expect(result.errors).toContain('Configuration error: COOKIE_SECRET must contain at least 32 characters. Fix: set COOKIE_SECRET to a random string of at least 32 characters (for example `openssl rand -hex 32`) in the environment or env file.')
    expect(result.errors.find((line) => line.includes('IAM_AGENT_SECRET'))).toMatch(/IAM_AGENT_SECRET is not set/)
    expect(result.errors.find((line) => line.includes('PORT'))).toMatch(/PORT must be a number/)
    for (const line of result.errors) {
      expect(line).not.toContain(secret)
      expect(line.split('\n')).toHaveLength(1)
    }
  })
})

it('requires explicit HTTPS same-origin metadata configuration without reflecting invalid values',()=>{
 const configured={...valid,IAM_BROWSER_ISSUER:'https://identity.example.com',IAM_BROWSER_AUTHORIZATION_URL:'https://identity.example.com/auth/authorize',IAM_BROWSER_API_BASE_URL:'https://identity.example.com/api/oathweave'}
 expect(validateEnv(configured).ok).toBe(true)
 for(const override of [{IAM_BROWSER_API_BASE_URL:undefined},{IAM_BROWSER_ISSUER:undefined},{IAM_BROWSER_AUTHORIZATION_URL:'http://identity.example.com/auth'},{IAM_BROWSER_API_BASE_URL:'https://other.example.com/api'},{IAM_BROWSER_AUTHORIZATION_URL:'https://deploy:obviously-fake-secret@identity.example.com/auth'},{IAM_BROWSER_API_BASE_URL:'https://identity.example.com/api?token=obviously-fake'},{IAM_BROWSER_API_BASE_URL:'not-a-url'},{IAM_BROWSER_AUTHORIZATION_URL:'https://identity.example.com/auth#fragment'},{IAM_BROWSER_API_BASE_URL:'https://identity.example.com/api?'},{IAM_BROWSER_AUTHORIZATION_URL:'https://identity.example.com/auth#'}]){
  const result=validateEnv({...configured,...override});expect(result.ok).toBe(false)
  if(!result.ok)for(const line of result.errors){expect(line).not.toContain('obviously-fake-secret');expect(line).not.toContain('other.example.com')}
 }
 expect(validateEnv({...valid,IAM_BROWSER_ISSUER:'retained-legacy-setting'}).ok).toBe(true)
})
