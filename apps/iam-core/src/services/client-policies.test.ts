import { expect, it } from 'vitest';
import { parseClientPolicies } from './client-policies.js';
it('defaults to no machine clients and refuses privileged wildcard policies or built-in overrides', () => {
  expect(parseClientPolicies()).toEqual({});
  expect(() => parseClientPolicies('{"hive-router":{}}')).toThrow();
  expect(() => parseClientPolicies(JSON.stringify({ example: { audience: 'example', permissions: ['*'], rotationOwner: 'owner' } }))).toThrow();
  expect(parseClientPolicies(JSON.stringify({ example: { audience: 'example', rotationOwner: 'owner' } })).example?.permissions).toEqual([]);
});
it('keeps client_credentials tokens on the native issuer unless a policy selects the browser issuer', () => {
  const policies = parseClientPolicies(JSON.stringify({
    native: { audience: 'example', rotationOwner: 'owner' },
    browser: { audience: 'example', rotationOwner: 'owner', issuer: 'browser' },
  }));
  expect(policies.native?.issuer).toBe('native');
  expect(policies.browser?.issuer).toBe('browser');
  expect(() => parseClientPolicies(JSON.stringify({ example: { audience: 'example', rotationOwner: 'owner', issuer: 'https://identity.example.com' } }))).toThrow();
});
