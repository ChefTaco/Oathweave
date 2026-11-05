// Browser-safe identity contracts. This module and its dependencies contain only validators.
import { z } from 'zod'
import { CreateUserSchema, UpdateUserSchema, AssignRolesSchema, RotatePasswordSchema } from './users.js'
import { CreateRoleSchema, UpdateRoleSchema } from './roles.js'
import { CreateClientSchema, UpdateClientSchema } from './clients.js'
import { CreateServiceAccountSchema, UpdateServiceAccountSchema } from './service-accounts.js'
import { CreateSystemUserSchema, UpdateSystemUserSchema } from './system-users.js'
import { UpdatePasswordPolicySchema } from './password-policy.js'
const string = z.string(), nullable = string.nullable(), strings = z.array(string)
export const IamRoleSummarySchema = z.object({ name: string, label: string.optional() })
export const IamRoleAssignmentSchema = z.object({ roleId: string.optional(), grantedAt: string.optional(), grantedBy: nullable.optional(), role: IamRoleSummarySchema })
const userRecord = z.object({ id: string, email: string, username: string, displayName: nullable, active: z.boolean(),
  lockedUntil: nullable.optional(), failedAttempts: z.number().optional(), mfaEnabled: z.boolean().optional(), mfaVerifiedAt: nullable.optional(),
  passkeyCount: z.number().optional(), trustedDeviceCount: z.number().optional(), passwordChangedAt: nullable.optional(), lastLoginAt: nullable, createdAt: string })
export const IamUserSchema = userRecord.extend({ roles: z.array(IamRoleAssignmentSchema) })
export const IamRoleSchema = z.object({ id: string, name: string, label: string, description: nullable, permissions: strings, isSystem: z.boolean(), createdAt: string, updatedAt: string })
export const IamClientSchema = z.object({ id: string, name: string, description: nullable, active: z.boolean(), clientType: z.enum(['public','confidential']),
  redirectUris: strings, grantTypes: strings, allowedIps: strings.optional(), firstParty: z.boolean(), createdAt: string, updatedAt: string.optional() })
const serviceAccount = z.object({ id: string, name: string, description: nullable, active: z.boolean(), apiKeyPrefix: nullable.optional(), keyPrefix: nullable.optional(),
  allowedIps: strings.optional(), expiresAt: nullable.optional(), lastUsedAt: nullable, createdAt: string })
export const IamServiceAccountSchema = serviceAccount.extend({ roles: z.array(IamRoleAssignmentSchema), client: z.object({ name: string }).nullable().optional() })
export const IamSystemUserSchema = z.object({ id: string, userId: string, linuxUsername: string, sudoEnabled: z.boolean(), sshPublicKey: nullable.optional(),
  authorizedHosts: strings, createdAt: string, user: z.object({ email: string, username: string, displayName: nullable, active: z.boolean() }).nullable().optional() })
export const IamSessionSchema = z.object({ id: string, userId: string, ipAddress: nullable, userAgent: nullable, riskScore: z.number().optional(),
  riskFactors: z.union([strings,string,z.null()]).optional(), stepUpVerifiedAt: nullable.optional(), createdAt: string, expiresAt: string,
  user: z.object({ email: string, username: string, displayName: nullable }).nullable().optional() })
export const IamPasswordPolicySchema = z.object({ name: string, minLength: z.number(), maxLength: z.number(), requireUppercase: z.boolean(), requireLowercase: z.boolean(),
  requireNumbers: z.boolean(), requireSpecial: z.boolean(), maxAgeDays: z.number(), historyCount: z.number(), lockoutAttempts: z.number(), lockoutDurationMin: z.number() })
export const IamAuditStatsSchema = z.object({ totalEvents: z.number(), successCount: z.number(), failureCount: z.number(), deniedCount: z.number(), byCategory: z.record(string,z.number()) })
export const IamAuditEventSchema = z.object({ id: string, timestamp: string, eventType: string, category: string, actorId: nullable.optional(), actorType: string,
  actorEmail: nullable.optional(), ipAddress: nullable.optional(), hostName: nullable.optional(), resourceType: nullable.optional(), resourceId: nullable.optional(),
  action: string, outcome: string, source: nullable.optional(), detail: z.record(string,z.unknown()).nullable().optional() })
export const IamHealthResponseSchema = z.object({ status: string }).passthrough()
export const IamSuccessResponseSchema = z.object({ success: z.literal(true) })
export const IamUsersResponseSchema = z.object({ users: z.array(IamUserSchema), total: z.number(), page: z.number(), limit: z.number() })
export const IamUserMutationResponseSchema = z.object({ user: userRecord.extend({ roles: z.array(IamRoleAssignmentSchema).optional() }) })
export const IamRolesResponseSchema = z.object({ roles: z.array(IamRoleSchema) })
export const IamRoleResponseSchema = z.object({ role: IamRoleSchema })
export const IamClientsResponseSchema = z.object({ clients: z.array(IamClientSchema) })
// Native create replies retain serialized arrays; list/update replies expose decoded arrays.
export const IamClientMutationResponseSchema = z.object({ client: IamClientSchema.omit({createdAt:true}).extend({createdAt:string.optional(),redirectUris:z.union([strings,string]),grantTypes:z.union([strings,string])}) })
export const IamServiceAccountsResponseSchema = z.object({ serviceAccounts: z.array(IamServiceAccountSchema) })
export const IamServiceAccountMutationResponseSchema = z.object({ serviceAccount: serviceAccount.extend({roles:z.array(IamRoleAssignmentSchema).optional()}) })
export const IamCreatedServiceAccountResponseSchema = z.object({ id:string, apiKey:string, warning:string })
export const IamRotatedServiceAccountResponseSchema = z.object({ apiKey:string, warning:string })
export const IamSystemUsersResponseSchema = z.object({ systemUsers: z.array(IamSystemUserSchema) })
export const IamSystemUserResponseSchema = z.object({ systemUser:IamSystemUserSchema })
export const IamSessionsResponseSchema = z.object({ sessions:z.array(IamSessionSchema) })
export const IamAuditResponseSchema = z.object({ events:z.array(IamAuditEventSchema),total:z.number(),page:z.number(),limit:z.number() })
export const IamPasswordPolicyResponseSchema = z.object({ policy:IamPasswordPolicySchema })
export const CreateIamUserRequestSchema = CreateUserSchema
export const UpdateIamUserRequestSchema = UpdateUserSchema
export const IamAssignRolesRequestSchema = AssignRolesSchema
export const IamRotatePasswordRequestSchema = RotatePasswordSchema
export const CreateIamRoleRequestSchema = CreateRoleSchema
export const UpdateIamRoleRequestSchema = UpdateRoleSchema
export const CreateIamClientRequestSchema = CreateClientSchema
export const UpdateIamClientRequestSchema = UpdateClientSchema
export const CreateIamServiceAccountRequestSchema = CreateServiceAccountSchema
export const UpdateIamServiceAccountRequestSchema = UpdateServiceAccountSchema
export const CreateIamSystemUserRequestSchema = CreateSystemUserSchema
export const UpdateIamSystemUserRequestSchema = UpdateSystemUserSchema
export const UpdateIamPasswordPolicyRequestSchema = UpdatePasswordPolicySchema
export const BrowserConsentDetailsSchema = z.object({ clientName:string.max(200),clientDescription:string.max(2000).nullable(),audience:string.max(200),scope:string.max(1000),permissions:z.array(string.max(200)).max(100) })
export const BrowserAuthorizationResponseSchema = z.object({ code:string.min(1),state:string,iss:string })
export const BrowserTokenResponseSchema = z.object({ id_token:string.min(1),access_token:string.min(1),token_type:z.literal('Bearer'),expires_in:z.number().int().min(1).max(900) })
export const BrowserSessionResponseSchema = z.object({ principal:z.object({ sub:string.min(1),username:string.optional(),roles:strings,permissions:strings }) })

import { LoginSchema as OwnedLoginRequestSchema,MfaChallengeSchema as OwnedMfaChallengeRequestSchema,ForgotPasswordSchema as OwnedForgotPasswordRequestSchema,ResetPasswordSchema as OwnedResetPasswordRequestSchema,StepUpSchema as OwnedStepUpRequestSchema } from './auth.js'
export const LoginRequestSchema = OwnedLoginRequestSchema
export const MfaChallengeRequestSchema = OwnedMfaChallengeRequestSchema
export const ForgotPasswordRequestSchema = OwnedForgotPasswordRequestSchema
export const ResetPasswordRequestSchema = OwnedResetPasswordRequestSchema
export const StepUpRequestSchema = OwnedStepUpRequestSchema

import { PasskeyRegisterSchema as OwnedPasskeyRegisterRequestSchema,PasskeyAuthenticationSchema as OwnedPasskeyAuthenticationRequestSchema,PasskeyAuthenticationOptionsSchema as OwnedPasskeyAuthenticationOptionsRequestSchema,PasskeyOptionsResponseSchema as OwnedPasskeyOptionsResponseSchema,PasskeyCredentialSchema as OwnedPasskeyCredentialSchema,MfaStatusSchema as OwnedMfaStatusSchema,RecoveryCodesSchema as OwnedRecoveryCodesSchema } from './webauthn.js'
export const PasskeyRegisterRequestSchema = OwnedPasskeyRegisterRequestSchema
export const PasskeyAuthenticationRequestSchema = OwnedPasskeyAuthenticationRequestSchema
export const PasskeyAuthenticationOptionsRequestSchema = OwnedPasskeyAuthenticationOptionsRequestSchema
export const PasskeyOptionsResponseSchema = OwnedPasskeyOptionsResponseSchema
export const PasskeyCredentialSchema = OwnedPasskeyCredentialSchema
export const MfaStatusSchema = OwnedMfaStatusSchema
export const RecoveryCodesSchema = OwnedRecoveryCodesSchema

import { AuthorizeConsentSchema as OwnedAuthorizeConsentRequestSchema,TokenExchangeSchema as OwnedTokenExchangeRequestSchema } from './oauth.js'
export const AuthorizeConsentRequestSchema = OwnedAuthorizeConsentRequestSchema
export const TokenExchangeRequestSchema = OwnedTokenExchangeRequestSchema

import { EnrollmentRequestSchema as OwnedEnrollmentRequestSchema,EnrollmentLifecycleSchema as OwnedEnrollmentLifecycleRequestSchema,EnrollmentResultSchema as OwnedEnrollmentResultSchema,EnrollmentInventorySchema as OwnedEnrollmentInventorySchema,EnrollmentInstallationsSchema as OwnedEnrollmentInstallationsSchema,LegacyEnrollmentReceiptSchema as OwnedLegacyEnrollmentReceiptSchema } from './enrollments.js'
export const EnrollmentRequestSchema = OwnedEnrollmentRequestSchema
export const EnrollmentLifecycleRequestSchema = OwnedEnrollmentLifecycleRequestSchema
export const EnrollmentResultSchema = OwnedEnrollmentResultSchema
export const EnrollmentInventorySchema = OwnedEnrollmentInventorySchema
export const EnrollmentInstallationsSchema = OwnedEnrollmentInstallationsSchema
export const LegacyEnrollmentReceiptSchema = OwnedLegacyEnrollmentReceiptSchema

export const BrowserLoginResponseSchema = z.union([
  z.object({requiresMfa:z.literal(true),mfaToken:string.min(1),methods:strings}),
  z.object({requiresMfa:z.literal(false).optional(),sessionId:string.optional(),expiresIn:z.number().optional(),riskScore:z.number().optional(),riskFactors:strings.optional(),user:z.object({id:string,email:string,username:string,displayName:nullable,roles:strings,permissions:strings}).optional()})
])
export const BrowserResourceUserResponseSchema = z.object({user:z.object({id:string,username:string,displayName:nullable,roles:strings,permissions:strings})})

import { MfaVerifySchema, MfaDisableSchema } from './auth.js'
export const MfaVerifyRequestSchema = MfaVerifySchema
export const MfaDisableRequestSchema = MfaDisableSchema
export const MfaSetupResponseSchema = z.object({secret:string,qrDataUrl:string.startsWith('data:image/png;base64,')})
export const PasskeyCredentialsResponseSchema = z.object({data:z.array(PasskeyCredentialSchema)})
export const BrowserMessageResponseSchema = z.object({message:string})
export const BrowserOkResponseSchema = z.object({ok:z.literal(true)})
