import { prisma } from '../db/client.js'
import { credentialLookupIds } from './webauthn-credentials.js'
import { ApiError } from '../types/index.js'

export async function stepUpPasskeyOptions(userId: string, sessionId: string) {
  const credentials = await prisma.webAuthnCredential.findMany({
    where: { userId },
  })
  if (!credentials.length)
    throw new ApiError(400, 'MFA_UNAVAILABLE', 'No passkey is registered')
  const { getAuthenticationOptions } = await import('./webauthn-service.js')
  return getAuthenticationOptions(
    userId,
    credentials.map((value) => ({
      ...value,
      transports: JSON.parse(value.transports) as string[],
    })),
    sessionId + ':step-up',
  )
}

export async function verifyStepUpPasskey(
  userId: string,
  sessionId: string,
  response: Record<string, unknown>,
): Promise<void> {
  if (
    typeof response.id !== 'string' ||
    !/^[A-Za-z0-9_-]{1,2048}$/.test(response.id)
  )
    throw new ApiError(400, 'INVALID_CREDENTIALS', 'Invalid passkey response')
  const credential = await prisma.webAuthnCredential.findFirst({
    where: { userId, credentialId: { in: credentialLookupIds(response.id) } },
  })
  if (!credential)
    throw new ApiError(401, 'INVALID_CREDENTIALS', 'Unknown passkey')
  const { verifyAuthentication } = await import('./webauthn-service.js')
  const result = await verifyAuthentication(
    userId,
    response,
    {
      ...credential,
      credentialId: response.id,
      transports: JSON.parse(credential.transports) as string[],
    },
    sessionId + ':step-up',
  )
  if (!result.verified)
    throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid passkey assertion')
  const changed = await prisma.webAuthnCredential.updateMany({
    where: { id: credential.id, counter: credential.counter },
    data: {
      counter: result.authenticationInfo.newCounter,
      lastUsedAt: new Date(),
    },
  })
  if (changed.count !== 1)
    throw new ApiError(
      401,
      'INVALID_CREDENTIALS',
      'Passkey changed during verification; try again',
    )
}
