/**
 * The refresh-token retry window. Rotation consumes a refresh token; a client that sends it again
 * within REFRESH_RETRY_GRACE_SECONDS (two requests racing, or a retry after the response was lost)
 * is handed the successor pair that rotation already issued, not a new one. Nothing new is minted,
 * so a copied token presented in the window only gets the same successor as its rightful holder:
 * whichever of the two rotates it first makes the other's next use a replay, which revokes the
 * session as before (RFC 9700 §4.14.2). After the window every reuse is a replay.
 *
 * The successor is kept in Redis for the window only, sealed with a key derived from the consumed
 * token itself, which the server does not store: the entry is unreadable without that token.
 * Redis being unavailable disables the window and leaves strict reuse detection.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import type { TokenPair } from '../types/index.js'

export const REFRESH_RETRY_GRACE_SECONDS = 10

export interface GraceRedis {
  set(key: string, value: string, expiry: 'EX', seconds: number): Promise<unknown>
  get(key: string): Promise<string | null>
}

interface Sealed {
  readonly pair: TokenPair
  /** When the pair was issued (ms), so a repeat answer reports the time its access token has left. */
  readonly issuedAt: number
}

const derive = (label: string, rawToken: string) => createHash('sha256').update(`oathweave:refresh-grace:${label}\0${rawToken}`).digest()

async function bounded<T>(operation: Promise<T>, ms = 1000): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Refresh retry store unavailable')), ms) })])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export class RefreshGraceStore {
  constructor(private readonly redis: () => Promise<GraceRedis>, private readonly prefix: string) {}

  private key(rawToken: string): string {
    return `${this.prefix}:refresh-grace:${derive('key', rawToken).toString('hex')}`
  }

  /** Keep the pair `rawToken` was rotated into for the retry window. Best effort. */
  async remember(rawToken: string, pair: TokenPair, now = Date.now()): Promise<void> {
    try {
      const iv = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', derive('seal', rawToken), iv)
      const body = Buffer.concat([cipher.update(JSON.stringify({ pair, issuedAt: now } satisfies Sealed)), cipher.final()])
      const value = [iv, cipher.getAuthTag(), body].map((part) => part.toString('base64url')).join('.')
      await bounded((await this.redis()).set(this.key(rawToken), value, 'EX', REFRESH_RETRY_GRACE_SECONDS))
    } catch {
      // Without the entry a retry is treated as a replay, as it was before the window existed.
    }
  }

  /** The pair `rawToken` was rotated into, while the retry window lasts; null otherwise. */
  async recall(rawToken: string, now = Date.now()): Promise<TokenPair | null> {
    try {
      const value = await bounded((await this.redis()).get(this.key(rawToken)))
      if (!value) return null
      const [iv, tag, body] = value.split('.').map((part) => Buffer.from(part, 'base64url'))
      if (!iv || !tag || !body) return null
      const decipher = createDecipheriv('aes-256-gcm', derive('seal', rawToken), iv)
      decipher.setAuthTag(tag)
      const sealed = JSON.parse(Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')) as Sealed
      if (now - sealed.issuedAt > REFRESH_RETRY_GRACE_SECONDS * 1000) return null
      const elapsed = Math.floor((now - sealed.issuedAt) / 1000)
      return { ...sealed.pair, expiresIn: Math.max(0, sealed.pair.expiresIn - elapsed) }
    } catch {
      return null
    }
  }
}
