import { describe, it, expect } from 'vitest'
import { getClientIp, oathweaveTrustedProxies, resolveClientIp, trustedProxyList } from './ip.js'

function mockContext(headers: Record<string, string | undefined> = {}) {
  return {
    req: {
      header(name: string) {
        return headers[name.toLowerCase()]
      },
    },
  } as Parameters<typeof getClientIp>[0]
}

const proxy = ['127.0.0.1']

describe('getClientIp', () => {
  it('ignores proxy headers when the socket peer is not trusted', () => {
    expect(resolveClientIp({ forwarded: '1.2.3.4' }, '203.0.113.10', proxy)).toBe('203.0.113.10')
    expect(resolveClientIp({ forwarded: '1.2.3.4', realIp: '1.2.3.4' }, '203.0.113.10', [])).toBe('203.0.113.10')
  })

  // This test used to pin the leftmost entry ('1.2.3.4'). A proxy appends the address it saw to
  // whatever the caller sent, so the leftmost entry is caller-controlled: sending
  // `X-Forwarded-For: 1.2.3.4` through the proxy produced "1.2.3.4, <real address>" and the caller
  // was then rate limited, allowlisted and audited as 1.2.3.4. Only the entry the trusted proxy
  // itself appended (the rightmost) can be believed.
  it('uses the address the trusted proxy appended, not one the caller supplied', () => {
    expect(resolveClientIp({ forwarded: '1.2.3.4, 5.6.7.8', realIp: '2.2.2.2' }, '127.0.0.1', proxy)).toBe('5.6.7.8')
  })

  it('cannot be steered by a spoofed chain of any length', () => {
    for (const spoofed of ['10.0.0.1', '127.0.0.1', '127.0.0.1, 10.0.0.1', 'unknown', ' , ,'])
      expect(resolveClientIp({ forwarded: `${spoofed}, 198.51.100.7` }, '127.0.0.1', proxy)).toBe('198.51.100.7')
  })

  it('skips every trusted proxy tier from the right', () => {
    const tiers = ['127.0.0.1', '10.0.0.0/8']
    expect(resolveClientIp({ forwarded: '192.0.2.99, 198.51.100.7, 10.1.2.3' }, '127.0.0.1', tiers)).toBe('198.51.100.7')
    expect(resolveClientIp({ forwarded: '198.51.100.7, 10.1.2.3, 10.9.9.9' }, '::ffff:127.0.0.1', tiers)).toBe('198.51.100.7')
  })

  it('stops at an outer proxy that is not listed as trusted', () => {
    expect(resolveClientIp({ forwarded: '198.51.100.7, 192.0.2.50' }, '127.0.0.1', proxy)).toBe('192.0.2.50')
  })

  it('uses the origin of a request that started inside the trusted proxy tier', () => {
    expect(resolveClientIp({ forwarded: '10.0.0.5, 10.0.0.6' }, '10.0.0.7', ['10.0.0.0/24'])).toBe('10.0.0.5')
    expect(resolveClientIp({}, '10.0.0.7', ['10.0.0.0/24'])).toBe('10.0.0.7')
  })

  it('never returns a forwarded value that is not an IP address', () => {
    expect(resolveClientIp({ forwarded: 'not-an-address' }, '127.0.0.1', proxy)).toBe('127.0.0.1')
    expect(resolveClientIp({ forwarded: '198.51.100.7, _hidden, 10.0.0.2' }, '127.0.0.1', ['127.0.0.1', '10.0.0.2'])).toBe('10.0.0.2')
    expect(resolveClientIp({ realIp: 'x' }, '127.0.0.1', proxy)).toBe('127.0.0.1')
  })

  it('accepts forwarded addresses written with a port or brackets', () => {
    expect(resolveClientIp({ forwarded: '198.51.100.7:51234' }, '127.0.0.1', proxy)).toBe('198.51.100.7')
    expect(resolveClientIp({ forwarded: '[2001:db8::7]:443' }, '127.0.0.1', proxy)).toBe('2001:db8::7')
    expect(resolveClientIp({ forwarded: '2001:db8::7' }, '127.0.0.1', proxy)).toBe('2001:db8::7')
  })

  it('returns unknown when neither a peer nor trusted headers are available', () => {
    const c = mockContext({})
    expect(getClientIp(c)).toBe('unknown')
    expect(resolveClientIp({ forwarded: '198.51.100.7' }, undefined, proxy)).toBe('unknown')
  })

  it('trims whitespace from trusted forwarding headers', () => {
    expect(resolveClientIp({ forwarded: '  1.1.1.1 ,  9.8.7.6 ' }, '127.0.0.1', proxy)).toBe('9.8.7.6')
  })

  it('falls back to trusted x-real-ip only when x-forwarded-for is absent', () => {
    expect(resolveClientIp({ realIp: '10.0.0.1' }, '127.0.0.1', proxy)).toBe('10.0.0.1')
    expect(resolveClientIp({ forwarded: '', realIp: '10.0.0.1' }, '127.0.0.1', proxy)).toBe('10.0.0.1')
  })

  it('reads the existing comma-separated TRUSTED_PROXY_IPS format', () => {
    expect(trustedProxyList(' 127.0.0.1, ::1 ,10.200.0.0/24,')).toEqual(['127.0.0.1', '::1', '10.200.0.0/24'])
    expect(trustedProxyList('')).toEqual([])
  })

  it('keeps IPv4 wildcard entries in TRUSTED_PROXY_IPS working', () => {
    expect(resolveClientIp({ forwarded: '198.51.100.7, 10.4.5.6' }, '10.1.2.3', ['10.*.*.*'])).toBe('198.51.100.7')
    expect(resolveClientIp({ forwarded: '198.51.100.7' }, '11.1.2.3', ['10.*.*.*'])).toBe('11.1.2.3')
  })

  it('trusts no proxy when the list is empty', () => {
    expect(oathweaveTrustedProxies([]).has('127.0.0.1')).toBe(false)
    expect(resolveClientIp({ forwarded: '198.51.100.7', realIp: '198.51.100.8' }, '127.0.0.1', [])).toBe('127.0.0.1')
  })

  it('treats an IPv4-mapped peer as its IPv4 address', () => {
    expect(resolveClientIp({ forwarded: '198.51.100.7' }, '::ffff:127.0.0.1', proxy)).toBe('198.51.100.7')
    expect(resolveClientIp({}, '::ffff:203.0.113.10', proxy)).toBe('203.0.113.10')
    expect(resolveClientIp({ forwarded: '198.51.100.7' }, '127.0.0.1', ['::ffff:127.0.0.1'])).toBe('198.51.100.7')
  })

  it('matches IPv6 proxy entries however they are written', () => {
    expect(resolveClientIp({ forwarded: '198.51.100.7' }, '2001:db8::1', ['2001:DB8:0:0::1'])).toBe('198.51.100.7')
    expect(resolveClientIp({ forwarded: '198.51.100.7' }, '2001:db8::1', ['2001:db8::/32'])).toBe('198.51.100.7')
    expect(resolveClientIp({ forwarded: '2001:DB8::7' }, '127.0.0.1', proxy)).toBe('2001:db8::7')
  })

  it('skips empty forwarded entries and reads x-real-ip when only blanks were sent', () => {
    expect(resolveClientIp({ forwarded: '198.51.100.7, , 10.0.0.2,' }, '127.0.0.1', ['127.0.0.1', '10.0.0.2'])).toBe('198.51.100.7')
    expect(resolveClientIp({ forwarded: ' , ', realIp: '198.51.100.9' }, '127.0.0.1', proxy)).toBe('198.51.100.9')
  })

  it('reads at most 32 hops of a forwarded chain', () => {
    const chain = Array.from({ length: 40 }, (_, index) => `10.0.0.${index + 1}`).join(', ')
    expect(resolveClientIp({ forwarded: `198.51.100.7, ${chain}` }, '127.0.0.1', ['127.0.0.1', '10.0.0.0/24'])).toBe('10.0.0.9')
  })
})

