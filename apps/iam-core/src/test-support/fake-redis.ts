/**
 * Just enough of ioredis for the server's limiters, challenge stores and health checks, kept in
 * memory. Test files install it with
 *   vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
 */
import { EventEmitter } from 'node:events'

type Entry = { value: string; expiresAt?: number }
const strings = new Map<string, Entry>()
const sorted = new Map<string, number[]>()

function live(key: string): Entry | undefined {
  const entry = strings.get(key)
  if (entry?.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
    strings.delete(key)
    return undefined
  }
  return entry
}

export function resetFakeRedis(): void {
  strings.clear()
  sorted.clear()
}

export class FakeRedis extends EventEmitter {
  status = 'ready'
  constructor(..._args: unknown[]) {
    super()
  }
  async connect(): Promise<void> {}
  async quit(): Promise<'OK'> {
    return 'OK'
  }
  disconnect(): void {}
  duplicate(): FakeRedis {
    return new FakeRedis()
  }
  async ping(): Promise<'PONG'> {
    return 'PONG'
  }
  async get(key: string): Promise<string | null> {
    return live(key)?.value ?? null
  }
  async getdel(key: string): Promise<string | null> {
    const value = live(key)?.value ?? null
    strings.delete(key)
    return value
  }
  async del(...keys: string[]): Promise<number> {
    let count = 0
    for (const key of keys) if (strings.delete(key) || sorted.delete(key)) count++
    return count
  }
  async set(key: string, value: string, ...options: (string | number)[]): Promise<'OK' | null> {
    let expiresAt: number | undefined
    let onlyIfAbsent = false
    for (let index = 0; index < options.length; index++) {
      const option = String(options[index]).toUpperCase()
      if (option === 'EX') expiresAt = Date.now() + Number(options[++index]) * 1000
      else if (option === 'PX') expiresAt = Date.now() + Number(options[++index])
      else if (option === 'NX') onlyIfAbsent = true
    }
    if (onlyIfAbsent && live(key)) return null
    strings.set(key, { value: String(value), ...(expiresAt !== undefined ? { expiresAt } : {}) })
    return 'OK'
  }
  /** The TOTP replay script: SET the step when it is newer than the stored one. */
  async eval(_script: string, _keys: number, key: string, step: string, ttl: string): Promise<number> {
    const last = Number(live(key)?.value ?? '-1')
    if (Number(step) <= last) return 0
    strings.set(key, { value: step, expiresAt: Date.now() + Number(ttl) })
    return 1
  }
  async publish(): Promise<number> {
    return 0
  }
  async subscribe(): Promise<number> {
    return 0
  }
  pipeline() {
    const ops: (() => unknown)[] = []
    const set = (key: string) => sorted.get(key) ?? (sorted.set(key, []), sorted.get(key)!)
    const chain = {
      zremrangebyscore: (key: string, _min: string | number, max: string | number) => {
        ops.push(() => sorted.set(key, set(key).filter((score) => score > Number(max))))
        return chain
      },
      zadd: (key: string, score: number) => {
        ops.push(() => set(key).push(Number(score)))
        return chain
      },
      /** Remove ranks `start..stop` (inclusive, negative counts from the highest score), as Redis. */
      zremrangebyrank: (key: string, start: number, stop: number) => {
        ops.push(() => {
          const scores = set(key).sort((a, b) => a - b)
          const from = start < 0 ? Math.max(0, scores.length + start) : start
          const to = stop < 0 ? scores.length + stop : Math.min(stop, scores.length - 1)
          if (from > to) return 0
          scores.splice(from, to - from + 1)
          return to - from + 1
        })
        return chain
      },
      zcard: (key: string) => {
        ops.push(() => set(key).length)
        return chain
      },
      pexpire: () => {
        ops.push(() => 1)
        return chain
      },
      expire: () => {
        ops.push(() => 1)
        return chain
      },
      exec: async () => ops.map((op) => [null, op()]),
    }
    return chain
  }
}

export const ioredisModule = { Redis: FakeRedis, default: FakeRedis }

/** The audit queue without BullMQ: events are kept for assertions. */
export const auditEvents: { eventType: string; [key: string]: unknown }[] = []
export const auditQueueModule = {
  redisConnection: new FakeRedis(),
  auditQueue: {
    add: async (_name: string, event: { eventType: string }) => {
      auditEvents.push(event)
      return { id: String(auditEvents.length) }
    },
    close: async () => undefined,
  },
}
