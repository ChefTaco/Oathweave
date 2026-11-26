import { z } from 'zod'
import { IpAllowlistEntrySchema } from './ip-allowlist.js'
const VALID_GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'] as const

export const CreateClientSchema = z.object({
  name: z.string().min(2).max(128).regex(/^[a-z0-9-]+$/),
  description: z.string().optional(),
  // Deprecated: leave it out and the server generates the secret and returns it once.
  secret: z.string().min(16).optional(),
  clientType: z.enum(['public', 'confidential']).default('confidential'),
  redirectUris: z.array(z.url()).default([]),
  grantTypes: z.array(z.enum(VALID_GRANT_TYPES)).default(['authorization_code', 'refresh_token']),
  firstParty: z.boolean().default(false),
  allowedIps: z.array(IpAllowlistEntrySchema).default([]),
}).refine(
  (data) => data.clientType !== 'public' || data.secret === undefined,
  { error: 'Public clients have no secret', path: ['secret'] },
).refine(
  (data) => data.clientType !== 'public' || !data.grantTypes.includes('client_credentials'),
  { error: 'Public clients cannot use client_credentials grant', path: ['grantTypes'] },
)

export const UpdateClientSchema = z.object({
  description: z.string().optional(),
  active: z.boolean().optional(),
  redirectUris: z.array(z.url()).optional(),
  grantTypes: z.array(z.enum(VALID_GRANT_TYPES)).optional(),
  firstParty: z.boolean().optional(),
  allowedIps: z.array(IpAllowlistEntrySchema).optional(),
})

// Deprecated `secret`: leave it out and the server generates the new secret and returns it once.
export const RotateClientSecretSchema = z.object({
  secret: z.string().min(32).optional(),
})
