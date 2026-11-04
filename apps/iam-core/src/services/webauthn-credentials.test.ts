import { expect, it } from 'vitest'
import {
  credentialLookupIds,
  credentialOptionIds,
} from './webauthn-credentials.js'
it('supports old encoded credential IDs without changing IDs or ownership', () => {
  const id = 'fake-credential-id',
    legacy = Buffer.from(id).toString('base64url')
  expect(credentialLookupIds(id)).toEqual([id, legacy])
  expect(credentialOptionIds(legacy)).toContain(id)
  expect(credentialOptionIds('____')).toEqual(['____'])
})
