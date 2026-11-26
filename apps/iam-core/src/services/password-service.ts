import argon2 from 'argon2'

const OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
}

export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, OPTIONS)
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain, OPTIONS)
  } catch {
    return false
  }
}

let dummyHash: Promise<string> | undefined

/**
 * Spends the cost of one password verification and always fails. Sign-in runs it when there is no
 * usable account to check (an unknown name), so the response time does not tell an unknown
 * username from a wrong password.
 */
export async function verifyAgainstDummyHash(plain: string): Promise<false> {
  dummyHash ??= hashPassword('oathweave-timing-equaliser-not-a-credential')
  await verifyPassword(await dummyHash, plain)
  return false
}
