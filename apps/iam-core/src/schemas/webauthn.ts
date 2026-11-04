import { z } from 'zod'
export const PasskeyRegisterSchema = z.object({
  response: z.record(z.string(), z.unknown()),
  friendlyName: z.string().max(100).default(''),
})
export const PasskeyAuthenticationSchema = z.object({
  mfaToken: z.string().min(1).max(8192),
  response: z.record(z.string(), z.unknown()),
})
export const PasskeyAuthenticationOptionsSchema = z.object({
  mfaToken: z.string().min(1).max(8192),
})
export const PasskeyOptionsResponseSchema = z.object({
  data: z.record(z.string(), z.unknown()),
})
export const PasskeyCredentialSchema = z.object({
  id: z.string(),
  friendlyName: z.string(),
  deviceType: z.string(),
  backedUp: z.boolean(),
  credentialId: z.string(),
  lastUsedAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
})
export const MfaStatusSchema = z.object({
  enabled: z.boolean(),
  totpConfigured: z.boolean(),
  recoveryCodesRemaining: z.number().int().nonnegative(),
})
export const RecoveryCodesSchema = z.object({
  backupCodes: z.array(z.string()),
})
