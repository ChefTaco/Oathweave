import { parseClientPolicies, type ClientPolicy } from './client-policy-schema.js';
export { parseClientPolicies, type ClientPolicy } from './client-policy-schema.js';
// Config is local to this IAM install and takes effect only after a reviewed restart.
export const machineClientPolicies = parseClientPolicies(process.env.IAM_MACHINE_CLIENT_POLICIES);

/** What a client_credentials token for one client may carry. */
export interface ClientCredentialsPolicy {
  /** `aud` of its tokens; none when undefined. */
  readonly audience: string | undefined;
  /** Every permission its tokens may carry (the requested scope is narrowed to these). */
  readonly permissions: readonly string[];
  /** Token lifetime in seconds, never above JWT_ACCESS_TTL; JWT_ACCESS_TTL when undefined. */
  readonly lifetimeSeconds: number | undefined;
  readonly issuer: 'native' | 'browser';
}

/**
 * The built-in clients, as policies of the same shape operators write in
 * IAM_MACHINE_CLIENT_POLICIES (which may not redefine them; see client-policy-schema.ts).
 *
 * `hive-router` is the suite model gateway's console proxy. Its token can manage IAM, so writes
 * with it must name the console operator behind them (`x-hive-operator`, see privilege-guard.ts);
 * without that header the token is read-only.
 */
export const builtinClientPolicies: Readonly<Record<string, ClientCredentialsPolicy>> = Object.freeze({
  'hive-router': {
    audience: undefined,
    permissions: [
      'iam:policy:write',
      'iam:users:read',
      'iam:users:write',
      'iam:users:delete',
      'iam:roles:read',
      'iam:roles:write',
      'iam:groups:read',
      'iam:groups:write',
      'iam:sa:read',
      'iam:sa:write',
      'iam:sa:delete',
      'iam:clients:read',
      'iam:clients:write',
      'iam:audit:read',
      'iam:sessions:revoke',
      'iam:system:login',
      'iam:tokens:introspect',
    ],
    lifetimeSeconds: undefined,
    issuer: 'native',
  },
  'security-exporter': {
    audience: 'hive-router',
    permissions: ['iam:audit:read', 'router:security-events:read'],
    lifetimeSeconds: undefined,
    issuer: 'native',
  },
  'example-portal': {
    audience: 'example-portal',
    permissions: ['example-portal:read'],
    lifetimeSeconds: undefined,
    issuer: 'native',
  },
});

/** The client_credentials policy of a client: built in, or from IAM_MACHINE_CLIENT_POLICIES. */
export function clientCredentialsPolicy(clientId: string): ClientCredentialsPolicy | undefined {
  if (Object.hasOwn(builtinClientPolicies, clientId)) return builtinClientPolicies[clientId];
  const configured: ClientPolicy | undefined = Object.hasOwn(machineClientPolicies, clientId) ? machineClientPolicies[clientId] : undefined;
  return configured && {
    audience: configured.audience,
    permissions: configured.permissions,
    lifetimeSeconds: configured.lifetimeSeconds,
    issuer: configured.issuer,
  };
}
