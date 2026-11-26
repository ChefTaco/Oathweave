import { z } from 'zod'

/** OpenID Connect `prompt`: space-delimited none, login, consent, select_account. */
const prompt = z
  .string()
  .max(100)
  .regex(/^(?:none|login|consent|select_account)(?: (?:none|login|consent|select_account))*$/, 'prompt supports only none, login, consent and select_account')
/** OpenID Connect `max_age` in seconds; at most one year. */
const MAX_AGE_LIMIT = 31_536_000
/** The signed ticket a LOGIN_REQUIRED answer returned, repeated after signing in. */
const loginTicket = z.string().min(1).max(4096)

/** GET /oauth/authorize query parameters */
export const AuthorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.url(),
  response_type: z.string().min(1),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(['S256']).optional(),
  scope: z.string().optional(),
  state: z.string().optional(),
  nonce: z.string().min(16).max(256).optional(),
  prompt: prompt.optional(),
  max_age: z.string().regex(/^\d{1,9}$/).transform(Number).pipe(z.number().int().max(MAX_AGE_LIMIT)).optional(),
  login_ticket: loginTicket.optional(),
})

/** POST /oauth/authorize — user consent approval */
export const AuthorizeConsentSchema = z.object({
  consent: z.enum(['approve', 'deny']).optional(),
  clientId: z.string().min(1),
  redirectUri: z.url(),
  responseType: z.string().min(1),
  codeChallenge: z.string().optional(),
  codeChallengeMethod: z.enum(['S256']).optional(),
  scope: z.string().optional(),
  state: z.string().optional(),
  nonce: z.string().min(16).max(256).optional(),
  prompt: prompt.optional(),
  maxAge: z.number().int().min(0).max(MAX_AGE_LIMIT).optional(),
  loginTicket: loginTicket.optional(),
})

/** POST /oauth/authorize/cancel — the user abandoned sign-in or consent */
export const AuthorizeCancelSchema = AuthorizeConsentSchema.pick({
  clientId: true,
  redirectUri: true,
  responseType: true,
  codeChallenge: true,
  codeChallengeMethod: true,
  scope: true,
  state: true,
  nonce: true,
})
export const TokenExchangeSchema = z.object({
  grant_type: z.enum([
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'urn:ietf:params:oauth:grant-type:device_code',
    'urn:ietf:params:oauth:grant-type:token-exchange',
  ]),
  device_code: z.string().optional(),
  subject_token: z.string().optional(),
  subject_token_type: z.string().optional(),
  actor_token: z.string().optional(),
  actor_token_type: z.string().optional(),
  requested_token_type: z.string().optional(),
  audience: z.string().optional(),
  resource: z.string().optional(),
  code: z.string().optional(),
  redirect_uri: z.string().optional(),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
  code_verifier: z.string().optional(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  nonce: z.string().optional(),
})
