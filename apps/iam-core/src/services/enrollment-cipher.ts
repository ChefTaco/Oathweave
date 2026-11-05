import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
export function enrollmentCipher(secret: string) {
  const key = scryptSync(secret, 'oathweave-enrollment-receipt-v1', 32)
  return {
    encrypt(value: string): string {
      const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv)
      const body = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
      return [iv, cipher.getAuthTag(), body].map(part => part.toString('hex')).join(':')
    },
    decrypt(value: string): string {
      const parts = value.split(':')
      if (parts.length !== 3) throw new Error('Invalid enrollment envelope')
      const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(parts[0]!, 'hex'))
      cipher.setAuthTag(Buffer.from(parts[1]!, 'hex'))
      return Buffer.concat([cipher.update(Buffer.from(parts[2]!, 'hex')), cipher.final()]).toString('utf8')
    },
  }
}
