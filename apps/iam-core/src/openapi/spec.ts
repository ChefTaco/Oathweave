import { z, type ZodType } from 'zod'
import { BrowserOpenIdConfigurationSchema } from '../schemas/discovery.js'
import * as browserContracts from '../schemas/browser-contracts.js'
import { EnrollmentRequestSchema, EnrollmentLifecycleSchema, EnrollmentResultSchema, EnrollmentInventorySchema, LegacyEnrollmentReceiptSchema, EnrollmentInstallationsSchema } from '../schemas/enrollments.js'
import {
  AuthorizeQuerySchema,
  AuthorizeConsentSchema,
  TokenExchangeSchema,
} from '../schemas/oauth.js'
import { IAM_VERSION } from '../config/version.js'
import {
  LoginSchema,
  RefreshSchema,
  ChangePasswordSchema,
  MfaVerifySchema,
  MfaChallengeSchema,
  MfaDisableSchema,
  ForgotPasswordSchema,
  ResetPasswordSchema,
  StepUpSchema,
} from '../schemas/auth.js'
import {
  CreateUserSchema,
  UpdateUserSchema,
  AssignRolesSchema,
  RotatePasswordSchema,
} from '../schemas/users.js'
import { CreateRoleSchema, UpdateRoleSchema } from '../schemas/roles.js'
import {
  CreateClientSchema,
  RotateClientSecretSchema,
  UpdateClientSchema,
} from '../schemas/clients.js'
import {
  CreateServiceAccountSchema,
  UpdateServiceAccountSchema,
} from '../schemas/service-accounts.js'
import {
  CreateSystemUserSchema,
  UpdateSystemUserSchema,
} from '../schemas/system-users.js'

import {
  PasskeyRegisterSchema,
  PasskeyAuthenticationSchema,
  PasskeyAuthenticationOptionsSchema,
  PasskeyOptionsResponseSchema,
  PasskeyCredentialSchema,
  MfaStatusSchema,
  RecoveryCodesSchema,
} from '../schemas/webauthn.js'

// ── Helpers ──

function zod(schema: ZodType) {
  return z.toJSONSchema(schema, {
    target: 'openapi-3.0',
    // Request bodies: fields with defaults are optional for the caller.
    io: 'input',
    override: ({ zodSchema, jsonSchema }) => {
      // Keep the published contract stable with the previous zod-to-json-schema
      // output: objects are documented as closed, and string formats are
      // described by `format` alone rather than zod's internal regexes.
      if (
        zodSchema._zod.def.type === 'object' &&
        jsonSchema.additionalProperties === undefined
      ) {
        jsonSchema.additionalProperties = false
      }
      if (
        typeof jsonSchema.format === 'string' &&
        typeof jsonSchema.pattern === 'string'
      ) {
        delete jsonSchema.pattern
      }
    },
  })
}

function ref(name: string) {
  return { $ref: `#/components/schemas/${name}` }
}

function jsonBody(schemaRef: ReturnType<typeof ref>, description = '') {
  return {
    required: true,
    description,
    content: { 'application/json': { schema: schemaRef } },
  }
}

function success(schema: Record<string, unknown>, description = 'Success') {
  return { [200]: { description, content: { 'application/json': { schema } } } }
}

function created(schema: Record<string, unknown>, description = 'Created') {
  return { [201]: { description, content: { 'application/json': { schema } } } }
}

const err400 = {
  description: 'Validation error',
  content: { 'application/json': { schema: ref('ApiError') } },
}
const err401 = {
  description: 'Unauthorized',
  content: { 'application/json': { schema: ref('ApiError') } },
}
const err403 = {
  description: 'Forbidden',
  content: { 'application/json': { schema: ref('ApiError') } },
}
const err404 = {
  description: 'Not found',
  content: { 'application/json': { schema: ref('ApiError') } },
}
const err409 = {
  description: 'Conflict',
  content: { 'application/json': { schema: ref('ApiError') } },
}

function qp(
  name: string,
  description: string,
  required = false,
  schema: Record<string, unknown> = { type: 'string' },
) {
  return { name, in: 'query' as const, required, description, schema }
}

function pp(name: string, description: string) {
  return {
    name,
    in: 'path' as const,
    required: true,
    description,
    schema: { type: 'string' },
  }
}

// ── Build Spec ──

export function buildOpenApiSpec() {
  const tags = [
    { name: 'Health', description: 'Service health check' },
    {
      name: 'Auth',
      description: 'Authentication — login, MFA, token management',
    },
    { name: 'Users', description: 'User CRUD and role assignment' },
    { name: 'Roles', description: 'Role and permission management' },
    { name: 'Service Accounts', description: 'Service account management' },
    { name: 'Clients', description: 'OAuth/API client management' },
    { name: 'Tokens', description: 'Token introspection and management' },
    { name: 'Sessions', description: 'Session listing and revocation' },
    { name: 'System Users', description: 'Linux system user mapping' },
    { name: 'Audit', description: 'Audit log querying, streaming, and export' },
    { name: 'Password Policy', description: 'Password policy configuration' },
  ]

  const componentSchemas: Record<string, unknown> = {
    BrowserOpenIdConfiguration: zod(BrowserOpenIdConfigurationSchema),
    ...Object.fromEntries(Object.entries(browserContracts).map(([name,schema]) => [name.replace(/Schema$/, ''), z.toJSONSchema(schema, { target:'draft-2020-12', io:'input' })])),
    // Request schemas from Zod
    LoginRequest: zod(LoginSchema),
    ForgotPasswordRequest: zod(ForgotPasswordSchema),
    ResetPasswordRequest: zod(ResetPasswordSchema),
    StepUpRequest: zod(StepUpSchema),
    PasskeyRegisterRequest: zod(PasskeyRegisterSchema),
    PasskeyAuthenticationRequest: zod(PasskeyAuthenticationSchema),
    PasskeyAuthenticationOptionsRequest: zod(
      PasskeyAuthenticationOptionsSchema,
    ),
    PasskeyOptionsResponse: zod(PasskeyOptionsResponseSchema),
    PasskeyCredential: zod(PasskeyCredentialSchema),
    MfaStatus: zod(MfaStatusSchema),
    RecoveryCodes: zod(RecoveryCodesSchema),
    AuthorizeConsentRequest: zod(AuthorizeConsentSchema),
    TokenExchangeRequest: zod(TokenExchangeSchema),
    RefreshRequest: zod(RefreshSchema),
    ChangePasswordRequest: zod(ChangePasswordSchema),
    MfaVerifyRequest: zod(MfaVerifySchema),
    MfaChallengeRequest: zod(MfaChallengeSchema),
    MfaDisableRequest: zod(MfaDisableSchema),
    CreateUserRequest: zod(CreateUserSchema),
    UpdateUserRequest: zod(UpdateUserSchema),
    AssignRolesRequest: zod(AssignRolesSchema),
    RotatePasswordRequest: zod(RotatePasswordSchema),
    CreateRoleRequest: zod(CreateRoleSchema),
    UpdateRoleRequest: zod(UpdateRoleSchema),
    CreateClientRequest: zod(CreateClientSchema),
    UpdateClientRequest: zod(UpdateClientSchema),
    RotateClientSecretRequest: zod(RotateClientSecretSchema),
    CreateServiceAccountRequest: zod(CreateServiceAccountSchema),
    EnrollmentRequest: zod(EnrollmentRequestSchema),
    EnrollmentLifecycleRequest: zod(EnrollmentLifecycleSchema),
    EnrollmentResult: zod(EnrollmentResultSchema),
    EnrollmentInventory: zod(EnrollmentInventorySchema),
    LegacyEnrollmentReceipt: zod(LegacyEnrollmentReceiptSchema),
    EnrollmentInstallations: zod(EnrollmentInstallationsSchema),
    UpdateServiceAccountRequest: zod(UpdateServiceAccountSchema),
    CreateSystemUserRequest: zod(CreateSystemUserSchema),
    UpdateSystemUserRequest: zod(UpdateSystemUserSchema),

    // Response schemas (hand-written)
    ApiError: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        message: { type: 'string' },
      },
    },
    User: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        username: { type: 'string' },
        email: { type: 'string' },
        displayName: { type: 'string' },
        status: { type: 'string', enum: ['ACTIVE', 'LOCKED', 'DISABLED'] },
        mfaEnabled: { type: 'boolean' },
        createdAt: { type: 'string', format: 'date-time' },
        updatedAt: { type: 'string', format: 'date-time' },
        roles: { type: 'array', items: ref('RoleSummary') },
      },
    },
    RoleSummary: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
      },
    },
    Role: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        description: { type: 'string' },
        permissions: { type: 'array', items: { type: 'string' } },
        isSystem: { type: 'boolean' },
        createdAt: { type: 'string', format: 'date-time' },
      },
    },
    Client: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        clientId: { type: 'string' },
        allowedIps: { type: 'string' },
        enabled: { type: 'boolean' },
        createdAt: { type: 'string', format: 'date-time' },
      },
    },
    ServiceAccount: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        description: { type: 'string' },
        keyPrefix: { type: 'string' },
        status: { type: 'string', enum: ['ACTIVE', 'DISABLED'] },
        allowedIps: { type: 'string' },
        createdAt: { type: 'string', format: 'date-time' },
      },
    },
    AuditEvent: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        eventType: { type: 'string' },
        category: { type: 'string' },
        action: { type: 'string' },
        outcome: { type: 'string', enum: ['SUCCESS', 'FAILURE', 'DENIED'] },
        actorType: { type: 'string' },
        actorId: { type: 'string' },
        actorEmail: { type: 'string' },
        ipAddress: { type: 'string' },
        hostName: { type: 'string' },
        timestamp: { type: 'string', format: 'date-time' },
      },
    },
    TokenInfo: {
      type: 'object',
      properties: {
        sub: { type: 'string' },
        email: { type: 'string' },
        roles: { type: 'array', items: { type: 'string' } },
        permissions: { type: 'array', items: { type: 'string' } },
        sessionId: { type: 'string' },
        exp: { type: 'number' },
        iat: { type: 'number' },
      },
    },
    Session: {
      type: 'object',
      required: ['id', 'userId', 'createdAt', 'expiresAt', 'revokedAt'],
      properties: {
        id: { type: 'string' }, userId: { type: 'string' },
        ipAddress: { type: ['string', 'null'] }, userAgent: { type: ['string', 'null'] },
        riskScore: { type: 'number' }, riskFactors: { type: ['string', 'null'] },
        deviceFingerprint: { type: ['string', 'null'] },
        createdAt: { type: 'string', format: 'date-time' },
        expiresAt: { type: 'string', format: 'date-time' },
        stepUpVerifiedAt: { type: ['string', 'null'], format: 'date-time' },
        revokedAt: { type: ['string', 'null'], format: 'date-time' },
        revokedBy: { type: ['string', 'null'] },
        user: { type: 'object', properties: { email: { type: 'string' }, username: { type: 'string' }, displayName: { type: ['string', 'null'] } } },
      },
    },
    PasswordPolicy: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        minLength: { type: 'integer' },
        requireUppercase: { type: 'boolean' },
        requireLowercase: { type: 'boolean' },
        requireNumbers: { type: 'boolean' },
        requireSpecial: { type: 'boolean' },
        maxAgeDays: { type: 'integer' },
        historyCount: { type: 'integer' },
      },
    },
  }

  const paths: Record<string, unknown> = {
    '/api/v1/sessions': {
      get: {
        tags: ['Sessions'], operationId: 'listSessions',
        summary: 'Review distinct active sessions; requires iam:sessions:revoke',
        security: [{ BearerAuth: [] }],
        responses: { ...success({ type: 'object', required: ['sessions'], properties: { sessions: { type: 'array', items: ref('Session') } } }), 401: err401, 403: err403 },
      },
    },
    '/api/v1/sessions/{id}': {
      delete: {
        tags: ['Sessions'], operationId: 'revokeSession', summary: 'Revoke an explicitly selected session and its refresh credentials',
        security: [{ BearerAuth: [] }], parameters: [pp('id', 'Exact session identity')],
        responses: { ...success({ type: 'object', properties: { success: { const: true } } }), 401: err401, 403: err403, 404: err404 },
      },
    },
    '/api/v1/sessions/user/{userId}': {
      delete: {
        tags: ['Sessions'], operationId: 'revokeAllUserSessions', summary: 'Explicitly revoke every session of the selected user',
        security: [{ BearerAuth: [] }], parameters: [pp('userId', 'Exact user identity')],
        responses: { ...success({ type: 'object', properties: { success: { const: true } } }), 401: err401, 403: err403 },
      },
    },
    '/api/v1/sessions/deduplicate': {
      post: {
        tags: ['Sessions'], operationId: 'deduplicateSessions', deprecated: true,
        summary: 'Refuse heuristic revocation; select explicit session IDs instead',
        description: 'Shared IP addresses and browser metadata do not establish that sessions are duplicates. Returns EXPLICIT_SESSION_SELECTION_REQUIRED without changing credentials.',
        security: [{ BearerAuth: [] }], responses: { 401: err401, 403: err403, 409: err409 },
      },
    },
    '/api/v1/browser/session': {
      get: {
        tags: ['Auth'],
        operationId: 'browserSession',
        summary: 'Read the revocable browser SSO principal',
        security: [{ BrowserSession: [] }],
        responses: { 200: { description: 'Current principal' }, 401: err401 },
      },
    },
    '/api/v1/browser/logout': {
      post: {
        tags: ['Auth'],
        operationId: 'browserLogout',
        summary: 'Revoke the browser session and its bound product access',
        security: [{ BrowserSession: [] }],
        responses: { 200: { description: 'Session revoked' }, 403: err403 },
      },
    },
    '/api/v1/oauth/authorize': {
      get: {
        tags: ['Auth'],
        operationId: 'oauthAuthorize',
        summary:
          'Authorize an exact registered redirect and S256 PKCE challenge',
        parameters: Object.entries(AuthorizeQuerySchema.shape).map(
          ([name, schema]) => ({ name, in: 'query', schema: zod(schema) }),
        ),
        responses: {
          200: { description: 'Consent request' },
          302: { description: 'Authorization response' },
          400: err400,
          401: err401,
        },
      },
      post: {
        tags: ['Auth'],
        operationId: 'oauthConsent',
        summary:
          'Approve authorization; registered first-party browser clients receive a session-bound code, state and issuer',
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: zod(AuthorizeConsentSchema) },
          },
        },
        responses: {
          200: { description: 'Authorization response' },
          400: err400,
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/oauth/token': {
      post: {
        tags: ['Auth'],
        operationId: 'oauthToken',
        summary:
          'Exchange a one-use authorization code with PKCE. Suite browser clients receive no refresh token.',
        security: [],
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: zod(TokenExchangeSchema) },
            'application/x-www-form-urlencoded': {
              schema: zod(TokenExchangeSchema),
            },
          },
        },
        responses: {
          200: {
            description:
              'Audience-restricted access token and optional ID token',
          },
          400: err400,
          401: err401,
        },
      },
    },
    // ── Health ──
    '/api/v1/health': {
      get: {
        tags: ['Health'],
        summary: 'Compatibility dependency health check',
        operationId: 'getHealth',
        responses: success({
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string' },
            authLimitsRelaxed: {
              type: 'boolean',
              description:
                'True while RELAX_AUTH_LIMITS testing mode raises sign-in throttles and disables failure lockout',
            },
            checks: { type: 'array', items: { type: 'object' } },
          },
        }),
      },
    },
    '/api/v1/health/live': {
      get: {
        tags: ['Health'],
        summary: 'Dependency-free liveness check',
        operationId: 'getHealthLive',
        responses: success({
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string' },
            authLimitsRelaxed: {
              type: 'boolean',
              description:
                'True while RELAX_AUTH_LIMITS testing mode raises sign-in throttles and disables failure lockout',
            },
            checks: { type: 'array', items: { type: 'object' } },
          },
        }),
      },
    },
    '/api/v1/health/ready': {
      get: {
        tags: ['Health'],
        summary: 'Readiness check for SQLite and Redis',
        operationId: 'getHealthReady',
        responses: success({
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string' },
            authLimitsRelaxed: {
              type: 'boolean',
              description:
                'True while RELAX_AUTH_LIMITS testing mode raises sign-in throttles and disables failure lockout',
            },
            checks: { type: 'array', items: { type: 'object' } },
          },
        }),
      },
    },
    '/api/v1/health/dependencies': {
      get: {
        tags: ['Health'],
        summary: 'Dependency health check for SQLite and Redis',
        operationId: 'getHealthDependencies',
        responses: success({
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string' },
            authLimitsRelaxed: {
              type: 'boolean',
              description:
                'True while RELAX_AUTH_LIMITS testing mode raises sign-in throttles and disables failure lockout',
            },
            checks: { type: 'array', items: { type: 'object' } },
          },
        }),
      },
    },

    // ── Auth ──
    '/api/v1/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Login with username and password',
        operationId: 'login',
        parameters: [
          {
            name: 'X-Oathweave-Browser',
            in: 'header',
            required: false,
            schema: { type: 'string', enum: ['true'] },
            description:
              'Opt into the approved-origin server-owned SSO session. Native access and refresh credentials are omitted from this response.',
          },
        ],
        requestBody: jsonBody(ref('LoginRequest')),
        responses: {
          ...success(
            {
              type: 'object',
              properties: {
                accessToken: { type: 'string' },
                refreshToken: { type: 'string' },
                expiresIn: { type: 'number' },
              },
            },
            'Native login returns credentials. Browser SSO mode returns a server-owned cookie and public profile without native access/refresh tokens.',
          ),
          400: err400,
          401: err401,
        },
      },
    },
    '/api/v1/auth/refresh': {
      post: {
        tags: ['Auth'],
        summary: 'Refresh access token',
        operationId: 'refreshToken',
        requestBody: jsonBody(ref('RefreshRequest')),
        responses: {
          ...success({
            type: 'object',
            properties: {
              accessToken: { type: 'string' },
              refreshToken: { type: 'string' },
              expiresIn: { type: 'number' },
            },
          }),
          401: err401,
        },
      },
    },
    '/api/v1/auth/logout': {
      post: {
        tags: ['Auth'],
        summary: 'Logout and revoke session',
        operationId: 'logout',
        security: [{ BearerAuth: [] }],
        responses: success({
          type: 'object',
          properties: { message: { type: 'string' } },
        }),
      },
    },
    '/api/v1/auth/me': {
      get: {
        tags: ['Auth'],
        summary: 'Get current authenticated user profile',
        operationId: 'getMe',
        security: [{ BearerAuth: [] }],
        responses: { ...success(ref('User')), 401: err401 },
      },
    },
    '/api/v1/auth/password': {
      post: {
        tags: ['Auth'],
        summary: 'Change password',
        operationId: 'changePassword',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('ChangePasswordRequest')),
        responses: {
          ...success({
            type: 'object',
            properties: { message: { type: 'string' } },
          }),
          400: err400,
          401: err401,
        },
      },
    },
    '/api/v1/auth/public-key': {
      get: {
        tags: ['Auth'],
        summary: 'Get JWT RS256 public key (PEM)',
        operationId: 'getPublicKey',
        responses: success({
          type: 'object',
          properties: { publicKey: { type: 'string' } },
        }),
      },
    },
    '/api/v1/auth/mfa/setup': {
      post: {
        tags: ['Auth'],
        summary: 'Initialize TOTP MFA setup',
        operationId: 'mfaSetup',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            required: ['secret', 'qrUri', 'qrDataUrl'],
            properties: {
              secret: { type: 'string' },
              qrUri: { type: 'string' },
              qrDataUrl: { type: 'string' },
            },
          }),
          401: err401,
        },
      },
    },
    '/api/v1/auth/mfa/verify': {
      post: {
        tags: ['Auth'],
        summary: 'Verify TOTP code to enable MFA',
        operationId: 'mfaVerify',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('MfaVerifyRequest')),
        responses: {
          ...success({
            type: 'object',
            required: ['message', 'backupCodes'],
            properties: {
              message: { type: 'string' },
              backupCodes: { type: 'array', items: { type: 'string' } },
            },
          }),
          400: err400,
          401: err401,
        },
      },
    },
    '/api/v1/auth/mfa/challenge': {
      post: {
        tags: ['Auth'],
        summary: 'Complete MFA challenge during login',
        operationId: 'mfaChallenge',
        requestBody: jsonBody(ref('MfaChallengeRequest')),
        responses: {
          ...success({
            type: 'object',
            properties: {
              accessToken: { type: 'string' },
              refreshToken: { type: 'string' },
              expiresIn: { type: 'number' },
            },
          }),
          400: err400,
          401: err401,
        },
      },
    },
    '/api/v1/auth/mfa/disable': {
      post: {
        tags: ['Auth'],
        summary: 'Disable MFA for current user',
        operationId: 'mfaDisable',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('MfaDisableRequest')),
        responses: {
          ...success({
            type: 'object',
            properties: { message: { type: 'string' } },
          }),
          400: err400,
          401: err401,
        },
      },
    },

    // ── Users ──
    '/api/v1/users': {
      get: {
        tags: ['Users'],
        summary: 'List users',
        operationId: 'listUsers',
        security: [{ BearerAuth: [] }],
        parameters: [
          qp('page', 'Page number', false, { type: 'integer', default: 1 }),
          qp('limit', 'Items per page', false, {
            type: 'integer',
            default: 50,
          }),
          qp('search', 'Search by username or email'),
          qp('status', 'Filter by status'),
        ],
        responses: {
          ...success({
            type: 'object',
            properties: {
              users: { type: 'array', items: ref('User') },
              total: { type: 'integer' },
            },
          }),
          401: err401,
          403: err403,
        },
      },
      post: {
        tags: ['Users'],
        summary: 'Create user',
        operationId: 'createUser',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('CreateUserRequest')),
        responses: {
          ...created(ref('User')),
          400: err400,
          401: err401,
          403: err403,
          409: err409,
        },
      },
    },
    '/api/v1/users/{id}': {
      get: {
        tags: ['Users'],
        summary: 'Get user by ID',
        operationId: 'getUser',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'User ID')],
        responses: { ...success(ref('User')), 401: err401, 404: err404 },
      },
      patch: {
        tags: ['Users'],
        summary: 'Update user',
        operationId: 'updateUser',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'User ID')],
        requestBody: jsonBody(ref('UpdateUserRequest')),
        responses: {
          ...success(ref('User')),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
      delete: {
        tags: ['Users'],
        summary: 'Delete user',
        operationId: 'deleteUser',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'User ID')],
        responses: {
          ...success({
            type: 'object',
            properties: { message: { type: 'string' } },
          }),
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },
    '/api/v1/users/{id}/roles': {
      post: {
        tags: ['Users'],
        summary: 'Assign roles to user',
        operationId: 'assignRoles',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'User ID')],
        requestBody: jsonBody(ref('AssignRolesRequest')),
        responses: {
          ...success(ref('User')),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },
    '/api/v1/users/{id}/rotate-password': {
      post: {
        tags: ['Users'],
        summary: 'Rotate and store a user password',
        operationId: 'rotateUserPassword',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'User ID')],
        requestBody: jsonBody(ref('RotatePasswordRequest')),
        responses: {
          ...success({
            type: 'object',
            properties: { success: { type: 'boolean' } },
          }),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },

    // ── Roles ──
    '/api/v1/roles': {
      get: {
        tags: ['Roles'],
        summary: 'List roles',
        operationId: 'listRoles',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            properties: { roles: { type: 'array', items: ref('Role') } },
          }),
          401: err401,
        },
      },
      post: {
        tags: ['Roles'],
        summary: 'Create role',
        operationId: 'createRole',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('CreateRoleRequest')),
        responses: {
          ...created(ref('Role')),
          400: err400,
          401: err401,
          403: err403,
          409: err409,
        },
      },
    },
    '/api/v1/roles/{id}': {
      get: {
        tags: ['Roles'],
        summary: 'Get role by ID',
        operationId: 'getRole',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Role ID')],
        responses: { ...success(ref('Role')), 401: err401, 404: err404 },
      },
      patch: {
        tags: ['Roles'],
        summary: 'Update role',
        operationId: 'updateRole',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Role ID')],
        requestBody: jsonBody(ref('UpdateRoleRequest')),
        responses: {
          ...success(ref('Role')),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
      delete: {
        tags: ['Roles'],
        summary: 'Delete role',
        operationId: 'deleteRole',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Role ID')],
        responses: {
          ...success({
            type: 'object',
            properties: { message: { type: 'string' } },
          }),
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },

    // ── Service Accounts ──
    '/api/v1/service-accounts': {
      get: {
        tags: ['Service Accounts'],
        summary: 'List service accounts',
        operationId: 'listServiceAccounts',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            properties: {
              serviceAccounts: { type: 'array', items: ref('ServiceAccount') },
            },
          }),
          401: err401,
        },
      },
      post: {
        tags: ['Service Accounts'],
        summary: 'Create service account',
        operationId: 'createServiceAccount',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('CreateServiceAccountRequest')),
        responses: {
          ...created(ref('ServiceAccount')),
          400: err400,
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/service-accounts/{id}': {
      patch: {
        tags: ['Service Accounts'],
        summary: 'Update service account',
        operationId: 'updateServiceAccount',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Service account ID')],
        requestBody: jsonBody(ref('UpdateServiceAccountRequest')),
        responses: {
          ...success(ref('ServiceAccount')),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
      delete: {
        tags: ['Service Accounts'],
        summary: 'Delete service account',
        operationId: 'deleteServiceAccount',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Service account ID')],
        responses: {
          ...success({
            type: 'object',
            properties: { message: { type: 'string' } },
          }),
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },
    '/api/v1/service-accounts/{id}/rotate': {
      post: {
        tags: ['Service Accounts'],
        summary: 'Rotate API key for service account',
        operationId: 'rotateServiceAccountKey',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Service account ID')],
        responses: {
          ...success({
            type: 'object',
            properties: {
              apiKey: { type: 'string' },
              message: { type: 'string' },
            },
          }),
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },

    // ── Clients ──
    '/api/v1/clients': {
      get: {
        tags: ['Clients'],
        summary: 'List clients',
        operationId: 'listClients',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            properties: { clients: { type: 'array', items: ref('Client') } },
          }),
          401: err401,
        },
      },
      post: {
        tags: ['Clients'],
        summary: 'Create client',
        operationId: 'createClient',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('CreateClientRequest')),
        responses: {
          ...created(ref('Client')),
          400: err400,
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/clients/{id}': {
      patch: {
        tags: ['Clients'],
        summary: 'Update client',
        operationId: 'updateClient',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Client ID')],
        requestBody: jsonBody(ref('UpdateClientRequest')),
        responses: {
          ...success(ref('Client')),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
      delete: {
        tags: ['Clients'],
        summary: 'Delete client',
        operationId: 'deleteClient',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Client ID')],
        responses: {
          ...success({
            type: 'object',
            properties: { message: { type: 'string' } },
          }),
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },
    '/api/v1/clients/{id}/rotate-secret': {
      post: {
        tags: ['Clients'],
        summary: 'Rotate a confidential client secret',
        operationId: 'rotateClientSecret',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Client ID')],
        requestBody: jsonBody(ref('RotateClientSecretRequest')),
        responses: {
          ...success({
            type: 'object',
            properties: { success: { type: 'boolean' } },
          }),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
          409: err409,
        },
      },
    },

    // ── Tokens ──
    '/api/v1/tokens/introspect': {
      post: {
        tags: ['Tokens'],
        summary: 'Introspect a JWT token',
        operationId: 'introspectToken',
        security: [{ BearerAuth: [] }],
        responses: { ...success(ref('TokenInfo')), 401: err401 },
      },
    },

    // ── System Users ──
    '/api/v1/system-users': {
      get: {
        tags: ['System Users'],
        summary: 'List system user mappings',
        operationId: 'listSystemUsers',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            properties: {
              systemUsers: { type: 'array', items: { type: 'object' } },
            },
          }),
          401: err401,
        },
      },
      post: {
        tags: ['System Users'],
        summary: 'Create system user mapping',
        operationId: 'createSystemUser',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('CreateSystemUserRequest')),
        responses: {
          ...created({ type: 'object' }),
          400: err400,
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/system-users/{id}': {
      patch: {
        tags: ['System Users'],
        summary: 'Update system user mapping',
        operationId: 'updateSystemUser',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'System user mapping ID')],
        requestBody: jsonBody(ref('UpdateSystemUserRequest')),
        responses: {
          ...success({ type: 'object' }),
          400: err400,
          401: err401,
          403: err403,
          404: err404,
        },
      },
      delete: {
        tags: ['System Users'],
        summary: 'Delete system user mapping',
        operationId: 'deleteSystemUser',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'System user mapping ID')],
        responses: {
          ...success({
            type: 'object',
            properties: { success: { type: 'boolean' } },
          }),
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },

    // ── Audit ──
    '/api/v1/audit': {
      get: {
        tags: ['Audit'],
        summary: 'Query audit events',
        operationId: 'queryAuditEvents',
        security: [{ BearerAuth: [] }],
        parameters: [
          qp('page', 'Page number', false, { type: 'integer', default: 1 }),
          qp('limit', 'Items per page', false, {
            type: 'integer',
            default: 50,
          }),
          qp('category', 'Filter by category'),
          qp('actorId', 'Filter by actor ID'),
          qp('outcome', 'Filter by outcome'),
          qp('eventType', 'Filter by event type'),
          qp('from', 'Start date (ISO 8601)'),
          qp('to', 'End date (ISO 8601)'),
        ],
        responses: {
          ...success({
            type: 'object',
            properties: {
              events: { type: 'array', items: ref('AuditEvent') },
              total: { type: 'integer' },
            },
          }),
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/audit/stats': {
      get: {
        tags: ['Audit'],
        summary: 'Get audit statistics (last 30 days)',
        operationId: 'getAuditStats',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            properties: {
              totalEvents: { type: 'integer' },
              successCount: { type: 'integer' },
              failureCount: { type: 'integer' },
              deniedCount: { type: 'integer' },
              byCategory: {
                type: 'object',
                additionalProperties: { type: 'integer' },
              },
            },
          }),
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/audit/export': {
      get: {
        tags: ['Audit'],
        summary: 'Export audit events as CSV, JSON, or syslog CEF',
        operationId: 'exportAuditEvents',
        security: [{ BearerAuth: [] }],
        parameters: [
          qp('format', 'Export format', false, {
            type: 'string',
            enum: ['csv', 'json', 'syslog'],
            default: 'csv',
          }),
          qp('from', 'Start date (ISO 8601)'),
          qp('to', 'End date (ISO 8601)'),
          qp('category', 'Filter by category'),
          qp('outcome', 'Filter by outcome'),
        ],
        responses: {
          200: {
            description: 'Export file download',
            content: {
              'text/csv': { schema: { type: 'string' } },
              'application/json': { schema: { type: 'object' } },
              'text/plain': { schema: { type: 'string' } },
            },
          },
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/audit/stream': {
      get: {
        tags: ['Audit'],
        summary: 'SSE live tail of audit events',
        operationId: 'streamAuditEvents',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Server-Sent Events stream',
            content: { 'text/event-stream': { schema: { type: 'string' } } },
          },
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/audit/ingest': {
      post: {
        tags: ['Audit'],
        summary: 'Ingest audit events from IAM agent',
        operationId: 'ingestAuditEvents',
        security: [{ AgentToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { type: 'array', items: { type: 'object' } },
            },
          },
        },
        responses: {
          ...success({
            type: 'object',
            properties: { ingested: { type: 'integer' } },
          }),
          401: err401,
        },
      },
    },

    // ── Password Policy ──
    '/api/v1/password-policy': {
      get: {
        tags: ['Password Policy'],
        summary: 'Get active password policy',
        operationId: 'getPasswordPolicy',
        security: [{ BearerAuth: [] }],
        responses: { ...success(ref('PasswordPolicy')), 401: err401 },
      },
      patch: {
        tags: ['Password Policy'],
        summary: 'Update password policy (admin only)',
        operationId: 'updatePasswordPolicy',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody({
          type: 'object',
          properties: {
            minLength: { type: 'integer' },
            requireUppercase: { type: 'boolean' },
            maxAgeDays: { type: 'integer' },
            historyCount: { type: 'integer' },
          },
        } as unknown as ReturnType<typeof ref>),
        responses: {
          ...success(ref('PasswordPolicy')),
          400: err400,
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/password-policy/strength': {
      post: {
        tags: ['Password Policy'],
        summary: 'Check password strength score',
        operationId: 'checkPasswordStrength',
        requestBody: jsonBody({
          type: 'object',
          properties: { password: { type: 'string' } },
          required: ['password'],
        } as unknown as ReturnType<typeof ref>),
        responses: {
          ...success({
            type: 'object',
            properties: {
              score: { type: 'integer' },
              label: { type: 'string' },
            },
          }),
        },
      },
    },
  }

  Object.assign(paths, {
    '/api/v1/auth/forgot-password': {
      post: {
        tags: ['Auth'],
        operationId: 'requestPasswordRecovery',
        summary:
          'Queue private out-of-band recovery; identical public responses for existing and unknown accounts',
        requestBody: jsonBody(ref('ForgotPasswordRequest')),
        responses: {
          200: { description: 'Recovery request queued' },
          503: { description: 'Recovery delivery is unavailable' },
        },
      },
    },
    '/api/v1/auth/reset-password': {
      post: {
        tags: ['Auth'],
        operationId: 'resetPassword',
        summary:
          'Consume an expiring one-use reset token and revoke prior sessions, refresh tokens and authorization codes',
        requestBody: jsonBody(ref('ResetPasswordRequest')),
        responses: {
          200: { description: 'Password replaced; sign in again' },
          400: err400,
        },
      },
    },
    '/api/v1/auth/mfa/status': {
      get: {
        tags: ['Auth'],
        operationId: 'getOwnMfaStatus',
        security: [{ BearerAuth: [] }],
        responses: { ...success(ref('MfaStatus')), 401: err401 },
      },
    },
    '/api/v1/auth/mfa/recovery-codes': {
      post: {
        tags: ['Auth'],
        operationId: 'replaceRecoveryCodes',
        summary:
          'Replace recovery codes after recent interactive authentication; plaintext is shown once',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success(ref('RecoveryCodes')),
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/auth/step-up/options': {
      post: {
        tags: ['Auth'],
        operationId: 'stepUpPasskeyOptions',
        security: [{ BrowserSession: [] }, { BearerAuth: [] }],
        responses: {
          ...success(ref('PasskeyOptionsResponse')),
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/auth/step-up': {
      post: {
        tags: ['Auth'],
        operationId: 'completeStepUp',
        summary:
          'Verify the password and an enabled MFA method for the current session',
        security: [{ BrowserSession: [] }, { BearerAuth: [] }],
        requestBody: jsonBody(ref('StepUpRequest')),
        responses: {
          200: { description: 'Session re-authenticated' },
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/mfa/webauthn/options': {
      get: {
        tags: ['Auth'],
        operationId: 'registerPasskeyOptions',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success(ref('PasskeyOptionsResponse')),
          401: err401,
          403: err403,
        },
      },
    },
    '/api/v1/mfa/webauthn/register': {
      post: {
        tags: ['Auth'],
        operationId: 'registerPasskey',
        security: [{ BearerAuth: [] }],
        requestBody: jsonBody(ref('PasskeyRegisterRequest')),
        responses: {
          200: { description: 'Passkey registered' },
          400: err400,
          403: err403,
        },
      },
    },
    '/api/v1/mfa/webauthn/authenticate-options': {
      get: {
        tags: ['Auth'],
        operationId: 'nativePasskeyAuthenticationOptions',
        summary:
          'Native compatibility; browsers use POST to keep challenge credentials out of URLs',
        parameters: [
          {
            name: 'mfaToken',
            in: 'query',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: { ...success(ref('PasskeyOptionsResponse')), 401: err401 },
      },
      post: {
        tags: ['Auth'],
        operationId: 'passkeyAuthenticationOptions',
        requestBody: jsonBody(ref('PasskeyAuthenticationOptionsRequest')),
        responses: { ...success(ref('PasskeyOptionsResponse')), 401: err401 },
      },
    },
    '/api/v1/mfa/webauthn/authenticate': {
      post: {
        tags: ['Auth'],
        operationId: 'authenticatePasskey',
        summary:
          'Verify a single-use MFA ceremony; browser opt-in returns only an HttpOnly SSO session',
        requestBody: jsonBody(ref('PasskeyAuthenticationRequest')),
        responses: {
          200: {
            description:
              'Authenticated; native token response or browser session',
          },
          400: err400,
          401: err401,
        },
      },
    },
    '/api/v1/mfa/webauthn/credentials': {
      get: {
        tags: ['Auth'],
        operationId: 'listOwnPasskeys',
        security: [{ BearerAuth: [] }],
        responses: {
          ...success({
            type: 'object',
            properties: {
              data: { type: 'array', items: ref('PasskeyCredential') },
            },
            required: ['data'],
          }),
          401: err401,
        },
      },
    },
    '/api/v1/mfa/webauthn/credentials/{id}': {
      delete: {
        tags: ['Auth'],
        operationId: 'deleteOwnPasskey',
        security: [{ BearerAuth: [] }],
        parameters: [pp('id', 'Passkey record identifier')],
        responses: {
          200: { description: 'Passkey removed' },
          401: err401,
          403: err403,
          404: err404,
        },
      },
    },
  })

  paths['/api/v1/enrollments'] = {
    get: { tags: ['Service Accounts'], summary: 'List explicitly coordinated identities for this installation', security: [{ BearerAuth: [] }], responses: { ...success(ref('EnrollmentInventory')), 401: err401, 403: err403, 503: { description: 'Enrollment APIs unconfigured' } } },
    post: { tags: ['Service Accounts'], summary: 'Durably enroll an explicitly scoped technical identity across product-owned APIs', security: [{ BearerAuth: [] }], requestBody: jsonBody(ref('EnrollmentRequest')), responses: { ...created(ref('EnrollmentResult')), 207: { description: 'Partial or unknown outcome; retry exact operation and policy', content: { 'application/json': { schema: ref('EnrollmentResult') } } }, 401: err401, 403: err403, 409: { description: 'Immutable policy, owner or lease conflict' }, 410: { description: 'Receipt unavailable; explicit review required' } } },
  }
  for (const action of ['rotate','disable']) paths[`/api/v1/enrollments/{actorId}/${action}`] = { post: { tags: ['Service Accounts'], summary: `Durably ${action} linked native identities without replacing product IDs`, security: [{ BearerAuth: [] }], parameters: [pp('actorId','Explicit enrollment ID')], requestBody: jsonBody(ref('EnrollmentLifecycleRequest')), responses: { ...success(ref('EnrollmentResult')), 207: { description: 'Incomplete operation; inspect and retry its existing ID', content: { 'application/json': { schema: ref('EnrollmentResult') } } }, 401: err401, 403: err403, 409: { description: 'Enrollment, policy or operation conflict' }, 410: { description: 'Receipt expired or acknowledged' } } } }
  paths['/api/v1/enrollments/{actorId}/operations/{operationId}'] = { get: { tags: ['Service Accounts'], summary: 'Recover an owned unexpired operation receipt', security: [{ BearerAuth: [] }], parameters: [pp('actorId','Explicit enrollment ID'),pp('operationId','Durable operation ID')], responses: { ...success(ref('EnrollmentResult')), 401: err401, 403: err403, 404: { description: 'Owned operation not found' } } } }
  paths['/api/v1/enrollments/{actorId}/operations/{operationId}/resume'] = { post: { tags: ['Service Accounts'], summary: 'Explicitly resume the same durable operation and immutable policy; never replay migrated unknown outcomes', security: [{ BearerAuth: [] }], parameters: [pp('actorId','Explicit enrollment ID'),pp('operationId','Existing durable operation ID')], responses: { ...success(ref('EnrollmentResult')), 207: { description: 'Operation remains incomplete' }, 401: err401, 403: err403, 409: { description: 'Legacy review, lease or policy conflict' } } } }
  paths['/api/v1/enrollments/{actorId}/operations/{operationId}/receipt'] = { delete: { tags: ['Service Accounts'], summary: 'Acknowledge all product and coordinator receipts without changing credentials', security: [{ BearerAuth: [] }], parameters: [pp('actorId','Explicit enrollment ID'),pp('operationId','Durable operation ID')], responses: { ...success({ type: 'object', properties: { ok: { type: 'boolean' } } }), 401: err401, 403: err403, 409: { description: 'Owned completed operation required' } } } }
  paths['/api/v1/enrollments/{actorId}/receipt'] = Object.fromEntries(['get','delete'].map(method => [method, { tags: ['Service Accounts'], summary: method === 'get' ? 'Recover an explicitly migrated legacy enrollment receipt before its original expiry' : 'Acknowledge an owned legacy enrollment receipt', security: [{ BearerAuth: [] }], parameters: [pp('actorId','Explicit migrated actor ID')], responses: { ...success(method === 'get' ? ref('LegacyEnrollmentReceipt') : { type: 'object' }), 401: err401, 403: err403, 410: { description: 'Original legacy receipt expired or acknowledged' } } }]))
  paths['/api/v1/enrollments/installations'] = { get: { tags: ['Service Accounts'], summary: 'List only explicitly authorized installation namespace identifiers; no endpoint configuration is exposed', security: [{ BearerAuth: [] }], responses: { ...success(ref('EnrollmentInstallations')), 401: err401, 403: err403 } } }
  for (const [path,item] of Object.entries(paths)) if (path.startsWith('/api/v1/enrollments') && path !== '/api/v1/enrollments/installations') for (const operation of Object.values(item as Record<string,{parameters?:unknown[]}>)) operation.parameters = [...(operation.parameters ?? []), qp('installationId','Exact installation namespace; mandatory when this authority coordinates multiple installations',false,{type:'string',pattern:'^[a-z0-9][a-z0-9-]{0,63}$'})]
  paths['/api/v1/oauth/.well-known/openid-configuration'] = { get: {
    tags: ['Auth'], operationId: 'discoverOpenIdConfiguration',
    summary: 'Native discovery by default; select an active registered public browser client for configured interactive metadata',
    parameters: [qp('client_id','Explicit IAM_BROWSER_CLIENT_POLICIES client identifier; never inferred from headers',false,{type:'string',pattern:'^hivexui-[a-z0-9-]+$'})],
    responses: {
      200: { description: 'Without client_id the native discovery document is unchanged. With client_id this is BrowserOpenIdConfiguration, with no-store caching.', content: { 'application/json': { schema: { anyOf: [ref('BrowserOpenIdConfiguration'), {type:'object',description:'Retained native discovery metadata',additionalProperties:true}] } } } },
      400: { description: 'Unknown, inactive, non-public, empty or repeated browser client selection' },
      503: { description: 'Explicit browser issuer, authorization portal and API base are not configured' },
    },
  } }
  const browserResponses: Array<[string,string,string,number]> = [
    ['/users','get','IamUsersResponse',200],['/users','post','IamUserMutationResponse',201],['/users/{id}','patch','IamUserMutationResponse',200],
    ['/roles','get','IamRolesResponse',200],['/roles','post','IamRoleResponse',201],['/roles/{id}','patch','IamRoleResponse',200],
    ['/clients','get','IamClientsResponse',200],['/clients','post','IamClientMutationResponse',201],['/clients/{id}','patch','IamClientMutationResponse',200],
    ['/service-accounts','get','IamServiceAccountsResponse',200],['/service-accounts','post','IamCreatedServiceAccountResponse',201],['/service-accounts/{id}','patch','IamServiceAccountMutationResponse',200],['/service-accounts/{id}/rotate','post','IamRotatedServiceAccountResponse',200],
    ['/system-users','get','IamSystemUsersResponse',200],['/system-users','post','IamSystemUserResponse',201],['/system-users/{id}','patch','IamSystemUserResponse',200],
    ['/sessions','get','IamSessionsResponse',200],['/audit','get','IamAuditResponse',200],['/audit/stats','get','IamAuditStats',200],['/password-policy','get','IamPasswordPolicyResponse',200],['/password-policy','patch','IamPasswordPolicyResponse',200]
  ];
  for(const [path,method,schema,status] of browserResponses){
    const operation=(paths['/api/v1'+path] as Record<string,{responses:Record<number,unknown>}>|undefined)?.[method];
    if(!operation)throw Error('Missing owned browser operation '+method+' '+path);
    operation.responses[status]={description:'Product-owned browser response',content:{'application/json':{schema:ref(schema)}}};
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'Hive IAM Core API',
      version: IAM_VERSION,
      description:
        'Centralized Identity & Access Management API for the Hive platform. Handles authentication (RS256 JWT), authorization (RBAC), user management, service accounts, audit logging, MFA, and password policies.',
    },
    servers: [
      { url: 'http://localhost:4200', description: 'Local development' },
    ],
    tags,
    components: {
      schemas: componentSchemas,
      securitySchemes: {
        BrowserSession: {
          type: 'apiKey',
          in: 'cookie',
          name: '__Host-oathweave_sso',
          description:
            'Secure HttpOnly browser session; unsafe requests require an allowed Origin',
        },
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description:
            'RS256 JWT access token obtained from POST /api/v1/auth/login',
        },
        AgentToken: {
          type: 'apiKey',
          in: 'header',
          name: 'x-agent-token',
          description: 'Shared secret for IAM agent authentication',
        },
        ClientSecret: {
          type: 'apiKey',
          in: 'header',
          name: 'x-client-secret',
          description: 'Client secret for OAuth client authentication',
        },
      },
    },
    paths,
  }
}
