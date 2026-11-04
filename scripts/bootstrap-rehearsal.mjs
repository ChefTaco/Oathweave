#!/usr/bin/env node
// Product-local, disposable SQLite proof. Never selects an operator store.
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import https from 'node:https'
import { createServer } from 'node:net'
import { randomBytes } from 'node:crypto'
const root = resolve(import.meta.dirname, '..')
const temporary = mkdtempSync(join(tmpdir(), 'oathweave-bootstrap-rehearsal-'))
const require = createRequire(join(root, 'apps/iam-core/package.json'))
const Database = require('better-sqlite3')
const home = join(temporary, 'data'),
  data = join(home, 'iam')
mkdirSync(home, { mode: 0o700 })
const suite = {
  schema: 1,
  adminId: 'synthetic-new-suite-admin',
  clients: [
    {
      id: 'hivexui-oathweave',
      audience: 'oathweave',
      permissions: ['iam:users:read', 'iam:clients:write'],
      redirectUris: ['https://console.example.com/auth/callback'],
      firstParty: true,
    },
    {
      id: 'hivexui-emberpath',
      audience: 'emberpath',
      permissions: ['router:providers:read'],
      redirectUris: ['https://console.example.com/auth/callback'],
      firstParty: true,
    },
  ],
}
const bootstrapFile = join(temporary, 'suite.json')
writeFileSync(bootstrapFile, JSON.stringify(suite), { mode: 0o600 })
async function port() {
  const listener = createServer().listen(0, '127.0.0.1')
  await new Promise((done) => listener.once('listening', done))
  const value = listener.address().port
  await new Promise((done) => listener.close(done))
  return value
}
const redisPort = await port(),
  apiPort = await port()
const key = join(temporary, 'tls.key'),
  certificate = join(temporary, 'tls.crt')
execFileSync(
  'openssl',
  [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    key,
    '-out',
    certificate,
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost',
    '-days',
    '1',
  ],
  { stdio: 'ignore' },
)
const redis = spawn(
  'redis-server',
  [
    '--bind',
    '127.0.0.1',
    '--port',
    String(redisPort),
    '--save',
    '',
    '--appendonly',
    'no',
  ],
  { cwd: temporary, stdio: 'ignore' },
)
await new Promise((done) => setTimeout(done, 100))
const environment = {
  PATH: process.env.PATH,
  NODE_ENV: 'production',
  HIVE_HOME: home,
  IAM_DATA_DIR: data,
  REDIS_URL: 'redis://127.0.0.1:' + redisPort,
  HOST: '127.0.0.1',
  PORT: String(apiPort),
  TLS_CERT_PATH: certificate,
  TLS_KEY_PATH: key,
  JWT_ISSUER: 'synthetic-native-issuer',
  IAM_BROWSER_ISSUER: 'https://identity.example.com',
  CORS_ORIGIN: 'https://console.example.com',
  COOKIE_SECRET: randomBytes(32).toString('hex'),
  IAM_AGENT_SECRET: randomBytes(32).toString('hex'),
  HIVE_AUTO_MIGRATE: 'true',
  HIVE_AUTO_UPGRADE: 'false',
  HIVE_UPDATE_CHECK: 'false',
  SEED_ADMIN_USERNAME: 'admin',
  SEED_ADMIN_EMAIL: 'alice@example.com',
  OATHWEAVE_SUITE_BOOTSTRAP_FILE: bootstrapFile,
  IAM_BROWSER_CLIENT_POLICIES: JSON.stringify(
    Object.fromEntries(
      suite.clients.map((client) => [
        client.id,
        { audience: client.audience, permissions: client.permissions },
      ]),
    ),
  ),
}
const cli = join(root, 'apps/iam-core/dist/cli.js')
async function run(env = environment) {
  const child = spawn(process.execPath, [cli, 'start'], {
    cwd: temporary,
    env,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  child.stdout.on('data', (part) => (output += part))
  child.stderr.on('data', (part) => (output += part))
  let ready = false
  for (let i = 0; i < 200; i++) {
    if (child.exitCode !== null) throw Error(output)
    try {
      ready = await new Promise((resolve) => {
        const request = https.get(
          {
            hostname: 'localhost',
            port: apiPort,
            path: '/api/v1/health/ready',
            ca: readFileSync(certificate),
          },
          (response) => {
            response.resume()
            resolve(response.statusCode === 200)
          },
        )
        request.on('error', () => resolve(false))
        request.setTimeout(1000, () => request.destroy())
      })
      if (ready) break
    } catch {}
    await new Promise((done) => setTimeout(done, 100))
  }
  try {
    process.kill(-child.pid, 'SIGTERM')
  } catch {}
  await new Promise((done) => {
    if (child.exitCode !== null) done()
    else child.once('close', done)
  })
  if (!ready) throw Error('Fresh identity did not become ready')
}
let passed = false
try {
  const child = spawn(process.execPath, [cli, 'start'], {
    cwd: temporary,
    env: environment,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = '',
    interrupted = false
  const timeout = setTimeout(() => {
    try {
      process.kill(-child.pid, 'SIGKILL')
    } catch {}
  }, 30000)
  child.stdout.on('data', (chunk) => {
    output += chunk.toString()
    if (!interrupted && output.includes('Seeding IAM database...')) {
      interrupted = true
      process.kill(-child.pid, 'SIGKILL')
    }
  })
  child.stderr.on('data', (chunk) => {
    output += chunk.toString()
  })
  await new Promise((done, reject) => {
    child.once('error', reject)
    child.once('close', done)
  })
  clearTimeout(timeout)
  writeFileSync(join(temporary, 'interruption.log'), output, { mode: 0o600 })
  assert(interrupted, 'Did not reach the transactional seed interruption point')
  assert(existsSync(join(data, '.bootstrap-pending.json')))
  assert(!existsSync(join(data, '.initialized')))
  const credentials = readFileSync(join(data, 'initial-credentials.env'))
  let db = new Database(join(data, 'iam.db'))
  assert.equal(
    db.prepare('SELECT count(*) AS n FROM users').get().n,
    0,
    'Interrupted seed committed a partial user',
  )
  assert.equal(
    db.prepare('SELECT count(*) AS n FROM clients').get().n,
    0,
    'Interrupted seed committed partial clients',
  )
  db.close()
  let changedRejected = false
  try {
    await run({
      ...environment,
      SEED_ADMIN_PASSWORD: 'different-obviously-fake-initial-password',
    })
  } catch (error) {
    changedRejected = String(error).includes('First-start inputs changed')
  }
  assert(changedRejected, 'Changed first-start inputs were accepted')
  await run()
  assert(!existsSync(join(data, '.bootstrap-pending.json')))
  assert(existsSync(join(data, '.initialized')))
  assert.deepEqual(
    readFileSync(join(data, 'initial-credentials.env')),
    credentials,
    'Retry regenerated initial credentials',
  )
  db = new Database(join(data, 'iam.db'))
  const before = db.prepare('SELECT id,passwordHash FROM users').all()
  assert.deepEqual(
    before.map((user) => user.id),
    [suite.adminId],
  )
  assert.equal(
    db
      .prepare(
        "SELECT count(*) AS n FROM clients WHERE clientType='public' AND secretHash IS NULL",
      )
      .get().n,
    2,
  )
  assert.equal(
    db
      .prepare(
        "SELECT count(*) AS n FROM user_role_assignments WHERE roleId IN (SELECT id FROM roles WHERE name='SUITE_ADMIN')",
      )
      .get().n,
    1,
  )
  db.close()
  await run()
  db = new Database(join(data, 'iam.db'))
  assert.deepEqual(
    db.prepare('SELECT id,passwordHash FROM users').all(),
    before,
    'Repeated startup changed identity or password',
  )
  db.close()
  // Direct suite seeding against a populated store must fail before any updates.
  const seed = join(root, 'apps/iam-core/dist/prisma/seed.js')
  let existingRejected = false
  try {
    execFileSync(process.execPath, [seed], {
      cwd: temporary,
      env: { ...environment, DATABASE_URL: 'file:' + join(data, 'iam.db') },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch (error) {
    existingRejected = String(error.stderr).includes(
      'requires an empty identity store',
    )
  }
  assert(existingRejected)
  const retainedMarker = join(data, '.bootstrap-pending.json')
  writeFileSync(retainedMarker, '{"operator":"retained-synthetic-marker"}', { mode: 0o600 })
  await run()
  assert.equal(readFileSync(retainedMarker, 'utf8'), '{"operator":"retained-synthetic-marker"}', 'Ordinary startup removed an unrelated existing marker')
  passed = true
  console.log(
    'PASS: interrupted atomic first seed, exact-input retry, stable credentials and IDs, public client registration, repeat startup and existing-store refusal.',
  )
} catch (error) {
  console.error('Disposable bootstrap evidence retained at ' + temporary)
  throw error
} finally {
  redis.kill('SIGTERM')
  await new Promise((done) => {
    if (redis.exitCode !== null) done()
    else redis.once('close', done)
  })
  if (passed) rmSync(temporary, { recursive: true, force: true })
}
