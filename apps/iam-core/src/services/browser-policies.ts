import { z } from 'zod'
import { machineClientPolicies } from './client-policies.js'

const browserPolicy = z
  .object({
    audience: z.string().min(1).max(200),
    permissions: z
      .array(z.string().regex(/^[a-z0-9-]+(?::[a-z0-9-]+)+$/))
      .max(100),
  })
  .strict()

export function parseBrowserPolicies(raw = '{}') {
  return Object.freeze(
    z
      .record(z.string().regex(/^hivexui-[a-z0-9-]+$/), browserPolicy)
      .parse(JSON.parse(raw)),
  )
}

export const browserClientPolicies = parseBrowserPolicies(
  process.env.IAM_BROWSER_CLIENT_POLICIES,
)

export function browserPermissions(
  clientId: string,
  granted: readonly string[],
): string[] {
  const policy = browserClientPolicies[clientId]
  if (!policy) return [...granted]
  return policy.permissions.filter(
    (permission) => granted.includes(permission) || granted.includes('*'),
  )
}

export function validateBrowserAuthorization(
  client: { clientType: string; redirectUris: string },
  params: {
    redirectUri: string
    codeChallenge?: string | undefined
    codeChallengeMethod?: string | undefined
  },
): void {
  const uris: unknown = JSON.parse(client.redirectUris)
  if (!Array.isArray(uris) || !uris.includes(params.redirectUri))
    throw new Error('Redirect URI must be registered exactly')
  if (
    client.clientType === 'public' &&
    (params.codeChallengeMethod !== 'S256' ||
      !/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge ?? ''))
  ) {
    throw new Error('Public clients require a valid S256 PKCE challenge')
  }
}

/** Browser credentials are short-lived even when native clients use a longer TTL. */
export function browserAccessLifetime(
  clientId: string | undefined,
  configured: number,
): number {
  return clientId && browserClientPolicies[clientId]
    ? Math.min(configured, 900)
    : configured
}

/** Machine clients whose policy selects the browser issuer for their client_credentials tokens. */
export function browserIssuedMachineClients(): string[] {
  return Object.keys(machineClientPolicies).filter(
    (id) => machineClientPolicies[id]!.issuer === 'browser',
  )
}

/** Keep native issuers stable while adding an HTTPS browser issuer. */
export function issuerForClient(
  clientId: string | undefined,
  nativeIssuer: string,
): string {
  if (
    !clientId ||
    (!browserClientPolicies[clientId] &&
      clientId !== 'oathweave-enrollment' &&
      machineClientPolicies[clientId]?.issuer !== 'browser')
  )
    return nativeIssuer
  const issuer = process.env.IAM_BROWSER_ISSUER || nativeIssuer
  const url = new URL(issuer)
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  )
    throw new Error('IAM_BROWSER_ISSUER must be an HTTPS issuer URL')
  return issuer
}
