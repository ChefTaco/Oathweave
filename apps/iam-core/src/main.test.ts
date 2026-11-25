import { EventEmitter } from 'node:events'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { serve } from '@hono/node-server'
import { startServer } from './main.js'

vi.mock('@hono/node-server', () => ({ serve: vi.fn() }))
vi.mock('./config/env.js', () => ({ env: { HOST: 'listener.example.com', PORT: 4200 } }))
vi.mock('./server.js', () => ({ createApp: () => ({ fetch: vi.fn() }) }))
vi.mock('./release/runtime.js', () => ({ startUpdateChecks: vi.fn() }))
vi.mock('./queue/audit-worker.js', () => ({ startAuditWorker: () => ({ close: vi.fn() }) }))
vi.mock('./services/audit-file-writer.js', () => ({ startAuditRetention: vi.fn(), stopAuditRetention: vi.fn() }))

afterEach(() => vi.restoreAllMocks())

describe('server startup logs', () => {
  it('reports readiness and bind failures without the configured address or raw error', async () => {
    const listener = new EventEmitter() as ReturnType<typeof serve>
    vi.mocked(serve).mockImplementation((_options, onListening) => {
      onListening?.({ address: 'listener.example.com', family: 'IPv4', port: 4200 })
      return listener
    })
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(process, 'on').mockReturnValue(process)
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('fixture exit') })

    await startServer()
    const error = Object.assign(new Error('fixture private detail'), { code: 'ENOTFOUND' })
    expect(() => listener.emit('error', error)).toThrow('fixture exit')
    expect(exit).toHaveBeenCalledWith(1)
    expect(log).toHaveBeenCalledWith('  ✓ Listening on port 4200')
    expect(errorLog.mock.calls).toEqual([['Startup error: cannot open the listener. Check HOST, PORT and the TLS settings.']])
    expect(JSON.stringify([log.mock.calls, errorLog.mock.calls])).not.toMatch(/listener\.example\.com|fixture private detail/u)
  })
})
