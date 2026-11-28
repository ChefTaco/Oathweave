// Side-effect free: the environment schema validates IAM_TOKEN_EXCHANGE_POLICIES with it.
import { z } from 'zod'

const permission = z.string().regex(/^[a-z0-9-]+(?::[a-z0-9-]+)+$/)
const audienceName = z.string().min(1).max(200)
const clientId = z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/)

/**
 * The server-owned identity that mints identity-enrollment delegations. Its policy is built into
 * the server (token-exchange.ts), so no configured policy may claim it.
 */
export const ENROLLMENT_ACTOR = 'oathweave-enrollment'

/** Subject token types a policy may accept, by their short RFC 8693 names. */
export const SUBJECT_TOKEN_TYPES = ['access_token', 'refresh_token'] as const
export type SubjectTokenTypeName = (typeof SUBJECT_TOKEN_TYPES)[number]

/**
 * Which tokens a client may exchange (RFC 8693) and what it may mint with them:
 *
 *   {"emberpath-service": {
 *      "subjectAudiences": ["emberpath"],
 *      "subjectTokenTypes": ["access_token"],
 *      "audiences": {"hivemem": {"permissions": ["hivemem:memories:read"], "lifetimeSeconds": 300,
 *                                "actors": ["agent-runner"]}}}}
 *
 * The client presents a person's access token issued to it, or addressed to one of
 * `subjectAudiences`, and receives a token for one of `audiences`, narrowed to the permissions
 * listed there that the person still holds. `subjectTokenTypes` (default `access_token` only)
 * opts in to presenting the person's refresh token instead; it must have been issued to this
 * client. `actors` lists the machine clients whose client_credentials token the client may
 * present as `actor_token` for that audience, so the minted token names that client as the
 * current actor (`act.sub`) with this client as the prior one (`act.act.sub`).
 */
const policySchema = z.object({
  subjectAudiences: z.array(audienceName).max(20).default([]),
  subjectTokenTypes: z.array(z.enum(SUBJECT_TOKEN_TYPES)).min(1).max(SUBJECT_TOKEN_TYPES.length).default(['access_token']),
  audiences: z.record(audienceName, z.object({
    permissions: z.array(permission).min(1).max(100),
    lifetimeSeconds: z.number().int().min(30).max(900).default(300),
    actors: z.array(clientId).max(50).default([]),
  }).strict()),
}).strict()

export type TokenExchangePolicy = z.infer<typeof policySchema>

export function parseTokenExchangePolicies(raw = '{}'): Readonly<Record<string, TokenExchangePolicy>> {
  return Object.freeze(
    z.record(clientId.refine((id) => id !== ENROLLMENT_ACTOR, { message: `${ENROLLMENT_ACTOR} is reserved for identity enrollment` }), policySchema)
      .parse(JSON.parse(raw)),
  )
}
