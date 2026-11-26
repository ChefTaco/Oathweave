import { describe, expect, it } from 'vitest'
import { RefreshGraceStore, REFRESH_RETRY_GRACE_SECONDS, type GraceRedis } from './refresh-grace.js'

function memory(): GraceRedis & { values: Map<string, { value: string; seconds: number }> } {
  const values = new Map<string, { value: string; seconds: number }>()
  return {
    values,
    async set(key, value, _expiry, seconds) {
      values.set(key, { value, seconds })
    },
    async get(key) {
      return values.get(key)?.value ?? null
    },
  }
}
const pair = { accessToken: 'access-fixture', refreshToken: 'refresh-fixture', sessionId: 'session-fixture', expiresIn: 900 }
const consumed = 'consumed-refresh-fixture-'.padEnd(64, 'x')

describe('the refresh retry store', () => {
  it('returns the successor for the window, with the access token time left', async () => {
    const redis = memory()
    const store = new RefreshGraceStore(async () => redis, 'fixture')
    await store.remember(consumed, pair, 1_000_000)
    expect([...redis.values.values()][0]!.seconds).toBe(REFRESH_RETRY_GRACE_SECONDS)
    expect(await store.recall(consumed, 1_004_000)).toEqual({ ...pair, expiresIn: 896 })
    expect(await store.recall(consumed, 1_000_000 + REFRESH_RETRY_GRACE_SECONDS * 1000 + 1)).toBeNull()
  })

  it('keeps nothing readable without the consumed token', async () => {
    const redis = memory()
    const store = new RefreshGraceStore(async () => redis, 'fixture')
    await store.remember(consumed, pair)
    const [key, entry] = [...redis.values.entries()][0]!
    expect(key).not.toContain(consumed)
    expect(entry.value).not.toContain('refresh-fixture')
    const other = 'another-token'.padEnd(64, 'y')
    expect(await store.recall(other)).toBeNull()
    // Copied under the other token's key, the sealed entry still does not open.
    redis.values.set((store as unknown as { key(raw: string): string }).key(other), entry)
    expect(await store.recall(other)).toBeNull()
  })

  it('turns the window off, not refresh, when Redis fails', async () => {
    const store = new RefreshGraceStore(async () => ({ set: () => Promise.reject(new Error('down')), get: () => Promise.reject(new Error('down')) }), 'fixture')
    await expect(store.remember(consumed, pair)).resolves.toBeUndefined()
    expect(await store.recall(consumed)).toBeNull()
  })
})
