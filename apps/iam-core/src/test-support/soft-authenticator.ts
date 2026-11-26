/**
 * A software WebAuthn authenticator for tests: one ES256 passkey that signs real assertions,
 * which @simplewebauthn/server verifies as it would a hardware one.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto'

export interface SoftPasskey {
  credentialId: string
  /** COSE public key, base64url, as Oathweave stores it. */
  publicKey: string
  assert: (options: { challenge: string; rpId: string; origin: string; counter: number; userVerified?: boolean }) => Record<string, unknown>
}

function coseKey(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string }
  const x = Buffer.from(jwk.x, 'base64url')
  const y = Buffer.from(jwk.y, 'base64url')
  // CBOR map: kty EC2 (1:2), alg ES256 (3:-7), crv P-256 (-1:1), x (-2), y (-3).
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x,
    Buffer.from([0x22, 0x58, 0x20]), y,
  ])
}

export function softPasskey(): SoftPasskey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const credentialId = randomBytes(16).toString('base64url')
  return {
    credentialId,
    publicKey: coseKey(publicKey).toString('base64url'),
    assert({ challenge, rpId, origin, counter, userVerified = true }) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }))
      const counterBytes = Buffer.alloc(4)
      counterBytes.writeUInt32BE(counter)
      // Flags: user present (0x01), and user verified (0x04) unless asked otherwise.
      const authenticatorData = Buffer.concat([
        createHash('sha256').update(rpId).digest(),
        Buffer.from([userVerified ? 0x05 : 0x01]),
        counterBytes,
      ])
      const signature = sign('sha256', Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]), privateKey)
      return {
        id: credentialId,
        rawId: credentialId,
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientDataJSON.toString('base64url'),
          authenticatorData: authenticatorData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
      }
    },
  }
}
