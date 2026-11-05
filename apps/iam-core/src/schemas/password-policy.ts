import { z } from 'zod'
export const UpdatePasswordPolicySchema = z.object({
  name: z.string().min(1).optional(),
  minLength: z.number().int().min(6).max(128).optional(),
  maxLength: z.number().int().min(8).max(256).optional(),
  requireUppercase: z.boolean().optional(),
  requireLowercase: z.boolean().optional(),
  requireNumbers: z.boolean().optional(),
  requireSpecial: z.boolean().optional(),
  maxAgeDays: z.number().int().min(0).max(365).optional(),
  historyCount: z.number().int().min(0).max(24).optional(),
  lockoutAttempts: z.number().int().min(1).max(100).optional(),
  lockoutDurationMin: z.number().int().min(1).max(1440).optional(),
})

