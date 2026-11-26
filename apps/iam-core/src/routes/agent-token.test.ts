/** The agent ingest secret is compared in constant time, safely for any header bytes. */
import { describe, expect, it, vi } from 'vitest'
vi.mock('ioredis', async () => (await import('../test-support/fake-redis.js')).ioredisModule)
vi.mock('../queue/audit-queue.js', async () => (await import('../test-support/fake-redis.js')).auditQueueModule)

const { startRealApp } = await import('../test-support/real-app.js')
const SECRET = 'agent-fixture-secret-0123'
const harness = await startRealApp({ IAM_AGENT_SECRET: SECRET })

const ingest = (token: string) =>
  harness.request('/api/v1/audit/ingest', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-token': token },
    body: JSON.stringify({ events: [] }),
  })

describe('POST /audit/ingest', () => {
  it('refuses a wrong token of the same length with 401, even when its bytes are longer', async () => {
    // Same string length as the secret, but U+00E9 is two bytes in UTF-8: a plain
    // timingSafeEqual on the buffers threw instead of refusing.
    const response = await ingest('é' + SECRET.slice(1))
    expect(response.status).toBe(401)
    expect((await ingest('x'.repeat(SECRET.length))).status).toBe(401)
  })
})
