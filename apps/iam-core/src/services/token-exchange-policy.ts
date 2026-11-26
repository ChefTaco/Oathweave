// Side-effect free: the environment schema validates IAM_TOKEN_EXCHANGE_POLICIES with it.
import { z } from 'zod'

const permission = z.string().regex(/^[a-z0-9-]+(?::[a-z0-9-]+)+$/)
const audienceName = z.string().min(1).max(200)

/**
 * Which tokens a client may exchange (RFC 8693) and what it may mint with them:
 *
 *   {"emberpath-service": {
 *      "subjectAudiences": ["emberpath"],
 *      "audiences": {"hivemem": {"permissions": ["hivemem:memories:read"], "lifetimeSeconds": 300}}}}
 *
 * The client presents a person's access token issued to it, or addressed to one of
 * `subjectAudiences`, and receives a token for one of `audiences`, narrowed to the permissions
 * listed there that the person still holds.
 */
const policySchema = z.object({
  subjectAudiences: z.array(audienceName).max(20).default([]),
  audiences: z.record(audienceName, z.object({
    permissions: z.array(permission).min(1).max(100),
    lifetimeSeconds: z.number().int().min(30).max(900).default(300),
  }).strict()),
}).strict()

export type TokenExchangePolicy = z.infer<typeof policySchema>

export function parseTokenExchangePolicies(raw = '{}'): Readonly<Record<string, TokenExchangePolicy>> {
  return Object.freeze(z.record(z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/), policySchema).parse(JSON.parse(raw)))
}
