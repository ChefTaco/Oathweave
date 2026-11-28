import type { Context } from 'hono'
import { getConnInfo } from '@hono/node-server/conninfo'
import { normalizeIpAddress, resolveClientAddress, type TrustedProxies } from '@hivemagnus/hive-common/rate-limit'
import { checkIpAllowlist } from './ip-allowlist.js'

function remoteAddress(c: Context): string | undefined {
  try {
    return getConnInfo(c).remote?.address;
  } catch {
    return undefined;
  }
}

/**
 * The `TRUSTED_PROXY_IPS` entries as a HiveCommon trusted-proxy set. The entries keep Oathweave's
 * format (exact addresses, CIDR ranges and IPv4 wildcards such as `10.*.*.*`), so they are matched
 * with `checkIpAllowlist` rather than parsed by HiveCommon `trustedProxies()`, which has no
 * wildcards. An empty list trusts no proxy.
 */
export function oathweaveTrustedProxies(entries: readonly string[]): TrustedProxies {
  const patterns = entries.map((entry) => normalizeIpAddress(entry) ?? entry)
  return {
    has: (address) => patterns.length > 0 && checkIpAllowlist(patterns, address),
    entries: patterns,
  }
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
  const trusted = oathweaveTrustedProxies(trustedProxies)
  // Oathweave has always skipped empty entries (`a, , b`); HiveCommon would stop at them.
  const forwardedFor = (headers.forwarded ?? '').split(',').map((entry) => entry.trim()).filter(Boolean).join(',')
  const client = resolveClientAddress({ peer: remote, forwardedFor, trusted })
  if (client.decision === 'proxy_without_forwarding' && headers.realIp !== undefined) {
    return normalizeIpAddress(headers.realIp) ?? client.address
  }
  return client.address
}

/** The configured trusted proxies: exact addresses, CIDR ranges or IPv4 wildcards, comma-separated. */
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
