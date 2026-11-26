import { CeremonyStore } from './ceremony-store.js'
import { credentialOptionIds } from './webauthn-credentials.js'
import { Redis } from 'ioredis'
import { env } from '../config/env.js'
/**
 * WebAuthn/FIDO2 service — registration & authentication ceremonies.
 *
 * Uses @simplewebauthn/server for attestation/assertion verification.
 * Challenges are bound to individual ceremonies and stored in Redis with a 5-minute TTL.
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server'

type AuthenticatorTransportFuture =
  | 'ble'
  | 'hybrid'
  | 'internal'
  | 'nfc'
  | 'usb'

const RP_NAME = env.WEBAUTHN_RP_NAME
const RP_ID = env.WEBAUTHN_RP_ID
const RP_ORIGIN = env.WEBAUTHN_RP_ORIGIN

// Single-use, purpose- and session-bound challenge store (5-min TTL).

const ceremonyRedis = new Redis(env.REDIS_URL, {
  lazyConnect: true,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 1,
  connectTimeout: 3000,
  commandTimeout: 5000,
})
ceremonyRedis.on('error', () => {
  /* Readiness and bounded ceremony errors report the dependency failure. */
})
void ceremonyRedis.connect().catch(() => undefined)
const ceremonies = new CeremonyStore(ceremonyRedis, env.REDIS_PREFIX)

// ── Types ──

interface StoredCredential {
  credentialId: string // Base64url
  publicKey: string // Base64url
  counter: number
  transports?: string[]
}

// ── Registration ──

export async function getRegistrationOptions(
  userId: string,
  userEmail: string,
  userName: string,
  existingCredentials: StoredCredential[],
  binding = '',
): Promise<ReturnType<typeof generateRegistrationOptions>> {
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName,
    userDisplayName: userEmail,
    attestationType: 'none',
    excludeCredentials: existingCredentials.flatMap((c) =>
      credentialOptionIds(c.credentialId).map((id) => ({
        id,
        transports: (c.transports ?? []) as AuthenticatorTransportFuture[],
      })),
    ),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
  })

  await ceremonies.save(userId, 'register', binding, options.challenge)
  return options
}

export async function verifyRegistration(
  userId: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  response: any,
  binding = '',
): Promise<VerifiedRegistrationResponse> {
  const expectedChallenge = await ceremonies.consume(
    userId,
    'register',
    binding,
    response,
  )
  if (!expectedChallenge) {
    throw new Error('Registration challenge expired or not found')
  }

  return verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: RP_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
  })
}

// ── Authentication ──

export async function getAuthenticationOptions(
  userId: string,
  existingCredentials: StoredCredential[],
  binding = '',
): Promise<ReturnType<typeof generateAuthenticationOptions>> {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: existingCredentials.flatMap((c) =>
      credentialOptionIds(c.credentialId).map((id) => ({
        id,
        transports: (c.transports ?? []) as AuthenticatorTransportFuture[],
      })),
    ),
    userVerification: 'required',
  })

  await ceremonies.save(userId, 'authenticate', binding, options.challenge)
  return options
}

export async function verifyAuthentication(
  userId: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  response: any,
  credential: StoredCredential,
  binding = '',
): Promise<VerifiedAuthenticationResponse> {
  const expectedChallenge = await ceremonies.consume(
    userId,
    'authenticate',
    binding,
    response,
  )
  if (!expectedChallenge) {
    throw new Error('Authentication challenge expired or not found')
  }

  const uint8Key = Buffer.from(credential.publicKey, 'base64url')

  return verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: RP_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
    credential: {
      id: credential.credentialId,
      publicKey: uint8Key,
      counter: credential.counter,
      transports: (credential.transports ??
        []) as AuthenticatorTransportFuture[],
    },
  })
}

// ── Passwordless sign-in (discoverable credentials) ──

/** The ceremony store's user slot for a sign-in whose user the passkey itself names. */
const DISCOVERABLE_SIGN_IN = 'discoverable-sign-in'

/**
 * Options for a passwordless sign-in: no allowCredentials, so the authenticator offers its
 * discoverable passkeys for this relying party, and user verification is required, so the
 * passkey alone is two factors (possession and the device PIN or biometric).
 */
export async function getPasswordlessOptions(
  ceremonyId: string,
): Promise<ReturnType<typeof generateAuthenticationOptions>> {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [],
    userVerification: 'required',
  })
  await ceremonies.save(DISCOVERABLE_SIGN_IN, 'authenticate', ceremonyId, options.challenge)
  return options
}

export async function verifyPasswordless(
  ceremonyId: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  response: any,
  credential: StoredCredential,
): Promise<VerifiedAuthenticationResponse> {
  const expectedChallenge = await ceremonies.consume(DISCOVERABLE_SIGN_IN, 'authenticate', ceremonyId, response)
  if (!expectedChallenge) throw new Error('Authentication challenge expired or not found')
  return verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: RP_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
    credential: {
      id: credential.credentialId,
      publicKey: Buffer.from(credential.publicKey, 'base64url'),
      counter: credential.counter,
      transports: (credential.transports ?? []) as AuthenticatorTransportFuture[],
    },
  })
}
