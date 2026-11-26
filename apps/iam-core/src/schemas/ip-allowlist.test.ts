import { describe, expect, it } from 'vitest'
import { IpAllowlistEntrySchema } from './ip-allowlist.js'
import { CreateClientSchema, UpdateClientSchema } from './clients.js'
import { checkIpAllowlist } from '../utils/ip-allowlist.js'

describe('IP allowlist entries', () => {
  const accepted = ['192.0.2.10', '10.0.0.0/8', '198.51.100.*', '10.*.*.*', '2001:db8::1', '2001:db8::/32', '::1']
  const refused = ['', 'example.com', '10.0.0.0/33', '2001:db8::/129', '300.1.1.1', '10.0.*', '*', '10.0.0.1/8/8']

  it('accepts every form the allowlist matcher supports', () => {
    for (const entry of accepted) expect(IpAllowlistEntrySchema.safeParse(entry).success, entry).toBe(true)
  })

  it('refuses entries the matcher could never match', () => {
    for (const entry of refused) expect(IpAllowlistEntrySchema.safeParse(entry).success, entry).toBe(false)
  })

  it('lets a client keep CIDR and IPv6 entries, and the matcher honours them', () => {
    const created = CreateClientSchema.parse({ name: 'ranged-client', secret: 'x'.repeat(32), allowedIps: ['10.0.0.0/8', '2001:db8::/32'] })
    expect(created.allowedIps).toEqual(['10.0.0.0/8', '2001:db8::/32'])
    expect(UpdateClientSchema.parse({ allowedIps: ['198.51.100.*'] }).allowedIps).toEqual(['198.51.100.*'])
    expect(checkIpAllowlist(created.allowedIps, '10.1.2.3')).toBe(true)
    expect(checkIpAllowlist(created.allowedIps, '2001:db8:1::5')).toBe(true)
    expect(checkIpAllowlist(created.allowedIps, '192.0.2.1')).toBe(false)
  })
})
