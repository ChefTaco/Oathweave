import { lstatSync, readFileSync, realpathSync } from 'node:fs'
import { isAbsolute } from 'node:path'
import { z } from 'zod'

const audiences = [
  'oathweave',
  'emberpath',
  'hivemem',
  'hiveskills',
  'cindertrace',
  'chattermost',
] as const
const permission = z.string().regex(/^[a-z0-9-]+(?::[a-z0-9-]+)+$/)
const callback = z.url().refine((value) => {
  const url = new URL(value)
  return (
    url.protocol === 'https:' &&
    !url.username &&
    !url.password &&
    !url.search &&
    !url.hash &&
    url.pathname === '/auth/callback'
  )
}, 'An exact HTTPS console callback is required')
const client = z
  .object({
    id: z.string().regex(/^hivexui-[a-z0-9-]+$/),
    audience: z.enum(audiences),
    permissions: z.array(permission).min(1).max(100),
    redirectUris: z.array(callback).length(1),
    firstParty: z.boolean(),
  })
  .strict()
  .superRefine((value, context) => {
    const prefix = (
      {
        oathweave: 'iam:',
        emberpath: 'router:',
        hivemem: 'hivemem:',
        hiveskills: 'hiveskills:',
        cindertrace: 'cindertrace:',
        chattermost: 'chattermost:',
      } as const
    )[value.audience]
    if (value.permissions.some((item) => !item.startsWith(prefix)))
      context.addIssue({
        code: 'custom',
        message: 'Browser grants must belong to the selected resource audience',
      })
  })
export const suiteBootstrapSchema = z
  .object({
    schema: z.literal(1),
    adminId: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/),
    clients: z.array(client).min(1).max(audiences.length),
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.clients.some((item) => item.audience === 'oathweave'))
      context.addIssue({
        code: 'custom',
        message: 'An Oathweave console client is required',
      })
    if (
      new Set(value.clients.map((item) => item.id)).size !==
        value.clients.length ||
      new Set(value.clients.map((item) => item.audience)).size !==
        value.clients.length
    )
      context.addIssue({
        code: 'custom',
        message: 'Duplicate bootstrap client or resource audience',
      })
    if (
      new Set(
        value.clients.map((item) => new URL(item.redirectUris[0]!).origin),
      ).size !== 1
    )
      context.addIssue({
        code: 'custom',
        message: 'All bootstrap clients must use the same console origin',
      })
  })
export type SuiteBootstrap = z.infer<typeof suiteBootstrapSchema>

/** Only first-start seeding consumes this protected, product-owned contract.
 * Existing accounts and client registrations are never inferred or relinked. */
export function loadSuiteBootstrap(
  source: NodeJS.ProcessEnv,
): SuiteBootstrap | undefined {
  const path = source.OATHWEAVE_SUITE_BOOTSTRAP_FILE
  if (!path) return undefined
  const state = lstatSync(path)
  if (
    !isAbsolute(path) ||
    !state.isFile() ||
    state.isSymbolicLink() ||
    realpathSync(path) !== path ||
    state.uid !== process.getuid?.() ||
    (state.mode & 0o077) !== 0
  )
    throw new Error(
      'Suite bootstrap must be a server-owned, mode-0600 regular file without symlinks',
    )
  const config = suiteBootstrapSchema.parse(
    JSON.parse(readFileSync(path, 'utf8')),
  )
  const policies = z
    .record(
      z.string(),
      z
        .object({ audience: z.string(), permissions: z.array(permission) })
        .strict(),
    )
    .parse(JSON.parse(source.IAM_BROWSER_CLIENT_POLICIES || '{}'))
  for (const item of config.clients) {
    const policy = policies[item.id]
    if (
      !policy ||
      policy.audience !== item.audience ||
      JSON.stringify([...new Set(policy.permissions)].sort()) !==
        JSON.stringify([...new Set(item.permissions)].sort())
    )
      throw new Error(
        'Suite bootstrap does not match configured browser permission ceilings',
      )
  }
  return config
}

export function suiteAdminPermissions(config: SuiteBootstrap): string[] {
  return [...new Set(config.clients.flatMap((item) => item.permissions))].sort()
}
