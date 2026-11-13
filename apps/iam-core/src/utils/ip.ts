import type { Context } from 'hono'
import { getConnInfo } from '@hono/node-server/conninfo'
import { isIP } from 'node:net'
import { checkIpAllowlist } from './ip-allowlist.js'

function remoteAddress(c: Context): string | undefined {
  try {
    return getConnInfo(c).remote?.address;
  } catch {
    return undefined;
  }
}

/** One `X-Forwarded-For` entry as a bare address, or undefined when it is not an IP address. */
function forwardedAddress(entry: string): string | undefined {
  let value = entry.trim()
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value)
  if (bracketed) value = bracketed[1]!
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) value = value.slice(0, value.lastIndexOf(':'))
  return isIP(value) ? value : undefined
}

/**
 * The client address of a request.
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
 * it. `X-Real-IP` is read only when a trusted proxy sent no `X-Forwarded-For` at all.
 */
export function resolveClientIp(
  headers: { forwarded?: string | undefined; realIp?: string | undefined },
  remote: string | undefined,
  trustedProxies: readonly string[],
): string {
  if (!remote) return 'unknown'
  if (trustedProxies.length === 0) return remote
  const trusted = (address: string) => checkIpAllowlist([...trustedProxies], address)
  if (!trusted(remote)) return remote

  const entries = (headers.forwarded ?? '').split(',').map((entry) => entry.trim()).filter(Boolean)
  if (entries.length === 0) {
    const realIp = headers.realIp === undefined ? undefined : forwardedAddress(headers.realIp)
    return realIp ?? remote
  }
  let nearest = remote
  for (let index = entries.length - 1; index >= 0; index--) {
    const address = forwardedAddress(entries[index]!)
    if (!address) return nearest
    if (!trusted(address)) return address
    nearest = address
  }
  return nearest
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
