import type { Context } from 'hono'
import { getConnInfo } from '@hono/node-server/conninfo'
import { isIP } from 'node:net'
import { normalizeIpAddress, resolveClientAddress, trustedProxies, type TrustedProxies } from '@hivemagnus/hive-common/rate-limit'

function remoteAddress(c: Context): string | undefined {
  try {
    return getConnInfo(c).remote?.address;
  } catch {
    return undefined;
  }
}

/** A `TRUSTED_PROXY_IPS` entry left out of the trusted set, and why. */
export interface IgnoredTrustedProxy {
  readonly entry: string
  readonly reason: string
}

/**
 * The `TRUSTED_PROXY_IPS` entries as a HiveCommon `trustedProxies()` set: exact addresses, CIDR
 * ranges, IPv4 wildcards such as `10.*.*.*` and the presets `loopback`, `private` and `linklocal`.
 * An empty list trusts no proxy.
 *
 * Entries are checked one at a time and an unusable one is left out (reported in `ignored`, which
 * the server logs) instead of stopping the server, as Oathweave has always run with them:
 * - an entry HiveCommon refuses: `10.*`, `010.*.*.*`, a wildcard with a prefix length,
 *   `10.0.0.0/33`, a host name. Oathweave matched none of these against any address. A CIDR
 *   prefix written loosely (`10.0.0.0/8x`) used to be read as its leading digits and is now left
 *   out too;
 * - an IPv6 range HiveCommon would also apply to IPv4 peers: one covering the IPv4-mapped range
 *   (`::/0` to `::/80`), or an IPv4-mapped network such as `::ffff:10.0.0.0/8`. Oathweave matched
 *   these against IPv6 addresses only, so trusting them now would trust IPv4 peers it never did.
 */
export function parseTrustedProxyIps(entries: readonly string[]): { trusted: TrustedProxies; ignored: IgnoredTrustedProxy[] } {
  const kept: string[] = []
  const ignored: IgnoredTrustedProxy[] = []
  for (const entry of entries) {
    let single: TrustedProxies
    try {
      single = trustedProxies([entry])
    } catch {
      ignored.push({ entry, reason: 'not an address, CIDR range, IPv4 wildcard (four parts) or preset; it never matched' })
      continue
    }
    if (entry.includes(':') && entry.includes('/')) {
      const network = single.entries[0]?.split('/')[0] ?? ''
      if (isIP(network) === 4 || single.has('0.0.0.0')) {
        ignored.push({ entry, reason: 'an IPv6 range that would also trust IPv4 peers; list IPv4 ranges separately' })
        continue
      }
    }
    kept.push(entry)
  }
  return { trusted: trustedProxies(kept), ignored }
}

let parsed: { key: string; trusted: TrustedProxies } | undefined

/** The trusted set for these entries, parsed once per distinct list; ignored entries are logged then. */
function trustedFor(entries: readonly string[]): TrustedProxies {
  const key = entries.join(',')
  if (parsed?.key !== key) {
    const { trusted, ignored } = parseTrustedProxyIps(entries)
    for (const { entry, reason } of ignored) console.warn(`TRUSTED_PROXY_IPS: ignoring ${JSON.stringify(entry)}: ${reason}`)
    parsed = { key, trusted }
  }
  return parsed.trusted
}

/** Parse `TRUSTED_PROXY_IPS` now, so an ignored entry is logged at startup rather than on the first request. */
export function checkTrustedProxyConfig(): void {
  trustedFor(trustedProxyList())
}

/**
 * The client address of a request, decided by HiveCommon `resolveClientAddress()`.
 *
 * Forwarding headers count only when the socket peer is a trusted proxy. Each proxy appends the
 * address it received the request from, so the rightmost `X-Forwarded-For` entry is the only one
 * the nearest proxy vouches for and everything to its left is whatever that proxy was sent. The
 * list is therefore read from the right: trusted proxies are skipped and the first address that is
 * not one is the client. Entries further left were supplied by that client and are never used. A
 * leftmost-entry rule would let any caller choose its own address by sending the header itself.
 *
 * When every entry is a trusted proxy the request started inside the proxy tier, and the leftmost
 * entry is its origin. An entry that is not an IP address ends the walk at the proxy that reported
 * it; empty entries are skipped. `X-Real-IP` is read only when a trusted proxy sent no
 * `X-Forwarded-For` at all. Addresses are normalised (an IPv4-mapped IPv6 peer is its IPv4
 * address, IPv6 is lowercase and compressed).
 */
export function resolveClientIp(
  headers: { forwarded?: string | undefined; realIp?: string | undefined },
  remote: string | undefined,
  trustedProxies: readonly string[],
): string {
  const trusted = trustedFor(trustedProxies)
  // Oathweave has always skipped empty entries (`a, , b`); HiveCommon would stop at them.
  const forwardedFor = (headers.forwarded ?? '').split(',').map((entry) => entry.trim()).filter(Boolean).join(',')
  const client = resolveClientAddress({ peer: remote, forwardedFor, trusted })
  if (client.decision === 'proxy_without_forwarding' && headers.realIp !== undefined) {
    return normalizeIpAddress(headers.realIp) ?? client.address
  }
  return client.address
}

/** The configured trusted proxies: exact addresses, CIDR ranges, IPv4 wildcards or presets, comma-separated. */
export function trustedProxyList(raw: string | undefined = process.env['TRUSTED_PROXY_IPS']): string[] {
  return (raw ?? '').split(',').map((entry) => entry.trim()).filter(Boolean)
}

/**
 * Extracts the real client IP from a Hono request context,
 * honouring proxy headers only from the proxies in `TRUSTED_PROXY_IPS` and
 * falling back to the connection's remote address.
 */
export function getClientIp(c: Context): string {
  return resolveClientIp(
    { forwarded: c.req.header('x-forwarded-for'), realIp: c.req.header('x-real-ip') },
    remoteAddress(c),
    trustedProxyList(),
  )
}
