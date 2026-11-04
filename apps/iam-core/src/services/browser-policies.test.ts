import { describe, expect, it } from 'vitest'
import {
  parseBrowserPolicies,
  validateBrowserAuthorization,
} from './browser-policies.js'

describe('public browser client boundaries', () => {
  const client = {
    clientType: 'public',
    redirectUris: '["https://console.example.com/callback"]',
  }
  const request = {
    redirectUri: 'https://console.example.com/callback',
    codeChallenge: 'a'.repeat(43),
    codeChallengeMethod: 'S256',
  }
  it('requires exact registered redirect URIs even for first-party clients', () => {
    expect(() => validateBrowserAuthorization(client, request)).not.toThrow()
    expect(() =>
      validateBrowserAuthorization({ ...client, redirectUris: '[]' }, request),
    ).toThrow()
    expect(() =>
      validateBrowserAuthorization(client, {
        ...request,
        redirectUri: request.redirectUri + '/extra',
      }),
    ).toThrow()
  })
  it('rejects missing, plain, malformed and downgraded PKCE', () => {
    for (const override of [
      { codeChallengeMethod: undefined },
      { codeChallengeMethod: 'plain' },
      { codeChallenge: 'short' },
      { codeChallenge: 'a'.repeat(44) },
    ]) {
      expect(() =>
        validateBrowserAuthorization(client, { ...request, ...override }),
      ).toThrow()
    }
  })
  it('permits only explicit resource permission ceilings', () => {
    expect(
      parseBrowserPolicies(
        '{"hivexui-emberpath":{"audience":"emberpath","permissions":["router:providers:read"]}}',
      ),
    ).toHaveProperty('hivexui-emberpath')
    expect(() =>
      parseBrowserPolicies(
        '{"hivexui-emberpath":{"audience":"emberpath","permissions":["*"]}}',
      ),
    ).toThrow()
    expect(() =>
      parseBrowserPolicies(
        '{"native-client":{"audience":"emberpath","permissions":[]}}',
      ),
    ).toThrow()
  })
})

it('caps only registered browser access credentials at fifteen minutes', async () => {
  const { vi } = await import('vitest')
  vi.stubEnv(
    'IAM_BROWSER_CLIENT_POLICIES',
    '{"hivexui-emberpath":{"audience":"emberpath","permissions":[]}}',
  )
  vi.resetModules()
  try {
    const { browserAccessLifetime } = await import('./browser-policies.js')
    expect(browserAccessLifetime('hivexui-emberpath', 3600)).toBe(900)
    expect(browserAccessLifetime('hivexui-emberpath', 300)).toBe(300)
    expect(browserAccessLifetime('native-client', 3600)).toBe(3600)
    expect(browserAccessLifetime(undefined, 3600)).toBe(3600)
  } finally {
    vi.unstubAllEnvs()
    vi.resetModules()
  }
})

it('preserves native issuers and uses a separately configured browser issuer', async () => {
  const { vi } = await import('vitest')
  vi.stubEnv(
    'IAM_BROWSER_CLIENT_POLICIES',
    '{"hivexui-emberpath":{"audience":"emberpath","permissions":[]}}',
  )
  vi.stubEnv('IAM_BROWSER_ISSUER', 'https://identity.example.com')
  vi.resetModules()
  try {
    const { issuerForClient } = await import('./browser-policies.js')
    expect(issuerForClient('native-client', 'legacy-issuer')).toBe(
      'legacy-issuer',
    )
    expect(issuerForClient('hivexui-emberpath', 'legacy-issuer')).toBe(
      'https://identity.example.com',
    )
    vi.stubEnv('IAM_BROWSER_ISSUER', '')
    expect(() =>
      issuerForClient('hivexui-emberpath', 'legacy-issuer'),
    ).toThrow()
    vi.stubEnv('IAM_BROWSER_ISSUER', 'http://identity.example.com')
    expect(() =>
      issuerForClient('hivexui-emberpath', 'legacy-issuer'),
    ).toThrow()
  } finally {
    vi.unstubAllEnvs()
    vi.resetModules()
  }
})
