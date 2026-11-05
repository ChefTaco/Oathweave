import { z } from 'zod'

/** Explicit browser profile; native discovery retains its existing contract. */
export const BrowserOpenIdConfigurationSchema = z.object({
  issuer: z.url(),
  authorization_endpoint: z.url(),
  token_endpoint: z.url(),
  userinfo_endpoint: z.url(),
  jwks_uri: z.url(),
  response_types_supported: z.tuple([z.literal('code')]),
  grant_types_supported: z.tuple([z.literal('authorization_code')]),
  subject_types_supported: z.tuple([z.literal('public')]),
  id_token_signing_alg_values_supported: z.tuple([z.literal('RS256')]),
  scopes_supported: z.array(z.enum(['openid', 'profile', 'email'])),
  token_endpoint_auth_methods_supported: z.tuple([z.literal('none')]),
  code_challenge_methods_supported: z.tuple([z.literal('S256')]),
  claims_supported: z.array(z.string()),
}).strict()
