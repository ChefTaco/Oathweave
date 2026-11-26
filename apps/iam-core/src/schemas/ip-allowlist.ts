import { z } from 'zod'

// Browser contracts bundle this file, so it may import only Zod.
const octet = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d|\\*)'
const wildcardV4 = new RegExp(`^(?=.*\\*)${octet}(?:\\.${octet}){3}$`)

/**
 * One IP allowlist entry, in a form `checkIpAllowlist` (utils/ip-allowlist.ts) matches: an exact
 * IPv4 or IPv6 address, an IPv4 or IPv6 CIDR range, or an IPv4 pattern with `*` octets.
 */
export const IpAllowlistEntrySchema = z.union([
  z.ipv4(),
  z.ipv6(),
  z.cidrv4(),
  z.cidrv6(),
  z.string().regex(wildcardV4),
], { error: 'must be an IPv4 or IPv6 address, a CIDR range, or an IPv4 pattern such as 10.0.*.*' })
