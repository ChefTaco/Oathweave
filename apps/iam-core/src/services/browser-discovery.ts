import { browserDiscoveryConfigurationSchema } from '../config/browser-discovery.js'
import { env } from '../config/env.js'
import { prisma } from '../db/client.js'
import { BrowserOpenIdConfigurationSchema } from '../schemas/discovery.js'
import { ApiError } from '../types/index.js'
import { browserClientPolicies } from './browser-policies.js'

export async function getBrowserOpenIdConfiguration(clientId: string) {
  if (!Object.hasOwn(browserClientPolicies, clientId)) throw new ApiError(
    400, 'INVALID_CLIENT', 'Select a registered public browser client',
  )
  const client = await prisma.client.findUnique({
    where: { id: clientId }, select: { active: true, clientType: true },
  })
  if (!client?.active || client.clientType !== 'public') throw new ApiError(
    400, 'INVALID_CLIENT', 'Select a registered public browser client',
  )
  const configuration = browserDiscoveryConfigurationSchema.safeParse(env)
  if (!configuration.success) throw new ApiError(
    503, 'BROWSER_DISCOVERY_UNCONFIGURED',
    'Configure IAM_BROWSER_ISSUER, IAM_BROWSER_AUTHORIZATION_URL and IAM_BROWSER_API_BASE_URL for browser discovery',
  )
  const values = configuration.data
  const api = values.IAM_BROWSER_API_BASE_URL.replace(/\/+$/, '')
  return BrowserOpenIdConfigurationSchema.parse({
    issuer: values.IAM_BROWSER_ISSUER,
    authorization_endpoint: values.IAM_BROWSER_AUTHORIZATION_URL,
    token_endpoint: api + '/oauth/token',
    userinfo_endpoint: api + '/oauth/userinfo',
    jwks_uri: api + '/oauth/jwks',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['sub', 'email', 'username', 'name', 'roles'],
  })
}
