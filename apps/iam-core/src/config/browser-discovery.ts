import { z } from 'zod'

/** Metadata comes from operator configuration, never request host/proxy headers. */
const metadataUrl = z.url().refine(value => {
  let url: URL
  try { url = new URL(value) } catch { return false }
  return url.protocol === 'https:' && !url.username && !url.password &&
    !url.search && !url.hash && !value.includes('?') && !value.includes('#') && !/[\u0000-\u0020\\]/.test(value)
}, 'must be an HTTPS URL without credentials, query, fragment or whitespace')

export const browserDiscoveryConfigurationSchema = z.object({
  IAM_BROWSER_ISSUER: metadataUrl,
  IAM_BROWSER_AUTHORIZATION_URL: metadataUrl,
  IAM_BROWSER_API_BASE_URL: metadataUrl,
}).superRefine((source, context) => {
  // Format issues are already reported above; cross-field validation must not throw.
  if (![source.IAM_BROWSER_ISSUER,source.IAM_BROWSER_AUTHORIZATION_URL,source.IAM_BROWSER_API_BASE_URL].every(value=>metadataUrl.safeParse(value).success)) return
  const origin = new URL(source.IAM_BROWSER_ISSUER).origin
  for (const name of ['IAM_BROWSER_AUTHORIZATION_URL', 'IAM_BROWSER_API_BASE_URL'] as const) {
    if (new URL(source[name]).origin !== origin) context.addIssue({
      code: 'custom', path: [name], message: 'must have the same origin as IAM_BROWSER_ISSUER',
    })
  }
})
