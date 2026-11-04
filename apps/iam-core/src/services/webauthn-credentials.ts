/** Older releases encoded an already-base64url ID a second time. Accept either
 * representation without rewriting a credential or inferring its ownership.
 * Authentication still verifies that record's public key, origin, RP and counter. */
export function credentialLookupIds(id: string): string[] {
  return [id, Buffer.from(id).toString('base64url')]
}

export function credentialOptionIds(id: string): string[] {
  const decoded = Buffer.from(id, 'base64url').toString('utf8')
  return /^[A-Za-z0-9_-]+$/.test(decoded) &&
    Buffer.from(decoded).toString('base64url') === id
    ? [...new Set([id, decoded])]
    : [id]
}
