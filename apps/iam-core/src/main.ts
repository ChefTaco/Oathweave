import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { createServer } from 'node:https'
import { serve } from '@hono/node-server'
import { createApp } from './server.js'
import { env } from './config/env.js'
import { startAuditWorker } from './queue/audit-worker.js'
import { startAuditRetention, stopAuditRetention } from './services/audit-file-writer.js'
import { IAM_VERSION } from './config/version.js'
import { authLimitsRelaxed, relaxedAuthLimitsWarning } from './config/auth-limits.js'

/**
 * Start the IAM HTTP(S) server. Shared by the systemd entry point
 * (`dist/index.js`) and the `hive-iam-server` CLI.
 */
export async function startServer(): Promise<void> {
  (await import('./release/runtime.js')).startUpdateChecks(IAM_VERSION);
  console.log(`Hive IAM Core v${IAM_VERSION} — starting...`)
  if (authLimitsRelaxed()) console.warn(relaxedAuthLimitsWarning())

  // Start BullMQ audit worker
  const worker = startAuditWorker()
  console.log('  ✓ Audit worker started')

  // Start audit file retention (prunes files older than AUDIT_MAX_AGE_DAYS)
  startAuditRetention()
  console.log('  ✓ Audit retention started')

  // Hourly: drop expired authorization codes and device sign-ins (expired rows grant nothing),
  // and revocation events past the feed's retention.
  // The modules load on first use; the app has them loaded by then.
  const pruneGrants = async () => {
    const { cleanupExpiredCodes } = await import('./services/oauth-service.js')
    const { cleanupExpiredDeviceAuthorizations } = await import('./services/device-authorization.js')
    const { pruneRevocationEvents } = await import('./services/revocation-events.js')
    await Promise.all([cleanupExpiredCodes(), cleanupExpiredDeviceAuthorizations(), pruneRevocationEvents()])
  }
  setInterval(() => void pruneGrants().catch(() => undefined), 3_600_000).unref()

  const app = createApp()

  // TLS config (optional — use a reverse proxy in production)
  const certPath = env.TLS_CERT_PATH ? resolve(env.TLS_CERT_PATH) : undefined
  const keyPath = env.TLS_KEY_PATH ? resolve(env.TLS_KEY_PATH) : undefined
  const useTls = certPath && keyPath && existsSync(certPath) && existsSync(keyPath)

  if (useTls) {
    console.log('  ✓ TLS certificates loaded')
  }

  const server = serve(
    {
      fetch: app.fetch,
      port: env.PORT,
      hostname: env.HOST,
      ...(useTls
        ? {
            createServer,
            serverOptions: {
              key: readFileSync(keyPath),
              cert: readFileSync(certPath),
            },
          }
        : {}),
    },
    (info) => {
      console.log(`  ✓ Listening on port ${info.port}`)
      console.log('  ✓ Public key endpoint: /api/v1/auth/public-key')
    },
  )

  server.once('error', (error: NodeJS.ErrnoException) => {
    if (error.code === 'EADDRINUSE') {
      console.error('Startup error: the configured port is already in use. Stop the other process or set PORT to a free port.')
    } else if (error.code === 'EACCES') {
      console.error('Startup error: permission denied. Set PORT to a port of 1024 or above or grant the required capability.')
    } else {
      console.error('Startup error: cannot open the listener. Check HOST, PORT and the TLS settings.')
    }
    process.exit(1)
  })

  let shuttingDown = false
  const shutdown = async () => {
    if (shuttingDown) return
    shuttingDown = true
    console.log('\nShutting down...')
    stopAuditRetention()
    await new Promise<void>((done) => server.close(() => done()))
    await worker.close()
    process.exit(0)
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}
