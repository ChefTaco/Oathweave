import { z } from 'zod'

export const LoginSchema = z.object({
  username: z.string().min(1).max(254),
  password: z.string().min(1).max(256),
})

export const RefreshSchema = z.object({
  refreshToken: z.string().min(1),
})

export const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(256),
  newPassword: z.string().min(8).max(256),
})

/**
 * Step-up verification of the current session: the password with the account's second factor
 * (TOTP code or passkey assertion), or a user-verified passkey assertion alone, as passwordless
 * sign-in accepts it (IAM_PASSWORDLESS_PASSKEYS).
 */
export const StepUpSchema = z
  .object({
    password: z.string().min(1).max(256).optional(),
    totpCode: z
      .string()
      .regex(/^[0-9]{6}$/)
      .optional(),
    assertion: z.record(z.string(), z.unknown()).optional(),
  })
  .strict()
  .refine((body) => body.password !== undefined || body.assertion !== undefined, {
    message: 'Send the password, or a passkey assertion',
    path: ['password'],
  })

export const MfaVerifySchema = z.object({
  code: z.string().min(6).max(6),
})

export const MfaChallengeSchema = z.object({
  mfaToken: z.string().min(1),
  code: z.string().min(1).max(12), // 6-digit TOTP or backup code
})

export const MfaDisableSchema = z.object({
  password: z.string().min(1).max(256),
  code: z.string().min(6).max(6),
})

export const ForgotPasswordSchema = z.object({
  email: z.email(),
})

export const ResetPasswordSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(8).max(256),
})
