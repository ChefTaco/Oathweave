// Side-effect free: the CLI validates configuration with it before env files load.
import { z } from 'zod';
const policySchema = z.object({
  audience: z.string().min(1).max(200),
  permissions: z.array(z.string().regex(/^[a-z0-9-]+(?::[a-z0-9-]+)+$/)).max(100).default([]),
  lifetimeSeconds: z.number().int().min(60).max(3600).default(900),
  rotationOwner: z.string().min(1).max(200),
  // native: tokens carry JWT_ISSUER. browser: tokens carry IAM_BROWSER_ISSUER, for a resource that
  // also verifies people on that issuer and relates the two (a service acting for a person).
  issuer: z.enum(['native', 'browser']).default('native'),
}).strict();
export type ClientPolicy = z.infer<typeof policySchema>;
const reserved = new Set(['hive-router', 'security-exporter', 'example-portal']);
export function parseClientPolicies(raw = '{}'): Readonly<Record<string, ClientPolicy>> {
  const policies = z.record(z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/), policySchema).parse(JSON.parse(raw));
  for (const key of Object.keys(policies)) if (reserved.has(key)) throw new Error(`Built-in policy cannot be overridden: ${key}`);
  return Object.freeze(policies);
}
