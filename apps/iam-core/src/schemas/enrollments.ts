import { z } from 'zod'

export const EnrollmentRequestSchema = z.object({
  agentId: z.string().min(2).max(32).regex(/^[a-z0-9_-]+$/),
  displayName: z.string().min(2).max(128),
  description: z.string().max(512).default(''),
  iamClientId: z.string().min(1).max(200),
  roleIds: z.array(z.string().min(1).max(200)).max(30).default([]),
  scopes: z.array(z.string().regex(/^[a-z][a-z0-9-]*(?::[a-z0-9-]+)+$/)).min(1).max(50)
    .refine(values => values.every(value => !value.startsWith('admin:')), 'Agent permissions must be explicit and non-admin'),
  hostLabel: z.string().max(128).default(''),
  workspaceId: z.string().min(1).max(100).regex(/^[a-z0-9_-]+$/).default('default'),
  owningProject: z.string().max(100).default(''),
  expiresHours: z.number().int().min(1).max(720).default(24),
  allowedIps: z.array(z.ipv4()).max(50).default([]),
}).strict()
export const EnrollmentLifecycleSchema = z.object({ operationId: z.uuid() }).strict()
export const EnrollmentInventorySchema = z.object({ installationId: z.string(), data: z.array(z.object({
  id: z.string(), kind: z.literal('service-account'), label: z.string(), status: z.enum(['active','inactive']),
  sources: z.array(z.string()), identifiers: z.record(z.string(), z.string().nullable()), capabilities: z.array(z.string()),
  linkedResourceCount: z.number(), lastActivityAt: z.iso.datetime().nullable(), enrollmentStatus: z.string(), credentialExpiresAt: z.iso.datetime().nullable(),
  latestOperation: z.object({ id: z.string(), action: z.string(), status: z.string() }).nullable(),
  legacyReceiptAvailable: z.boolean().optional(),
}).strict()) }).strict()
export const LegacyEnrollmentReceiptSchema = z.object({ actorId: z.string(), secrets: z.record(z.string(),z.string()), receiptExpiresAt: z.iso.datetime() }).strict()
export const EnrollmentInstallationsSchema = z.object({ installations: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/)) }).strict()
export const EnrollmentResultSchema = z.object({
  ok: z.boolean(), actorId: z.string(), action: z.enum(['enroll', 'rotate', 'disable']), operationId: z.string(),
  identifiers: z.record(z.string(), z.string().nullable()),
  secrets: z.record(z.string(), z.string()),
  steps: z.array(z.object({ service: z.string(), state: z.enum(['sent', 'completed', 'unknown']), status: z.number(), ok: z.boolean() }).strict()),
  receiptExpiresAt: z.iso.datetime().nullable(), remediation: z.string().nullable(),
}).strict()
