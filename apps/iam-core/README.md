# Oathweave server (`apps/iam-core`)

Oathweave is a self-hosted identity and access management server: OAuth 2.0 and
OpenID Connect, RS256-signed JWTs with a JWKS endpoint, role-based access
control, MFA (TOTP and WebAuthn/FIDO2), service accounts, sessions, and an
append-only audit trail. It is the identity service of the
[Hive](https://github.com/ChefTaco/hive) suite, and it also runs on its own.

> **How it is released.** Oathweave 2.x ships only as the container image
> `ghcr.io/cheftaco/oathweave`, tagged with its exact version. It is normally
> installed with the rest of the suite by `hive.sh`, the
> [Hive suite controller](https://github.com/ChefTaco/hive#install-the-suite),
> which writes its configuration and secrets and runs its Redis. The npm package
> `@hivemagnus/hive-iam-server` is the legacy Hive IAM 1.x line: `npm install` and
> `npx` resolve it to 1.2.2, not to this release. This workspace's package,
> `@hivemagnus/oathweave`, is not published on npm.

## Features

- RS256 access tokens, rotating refresh tokens, JWKS and OIDC discovery
- OAuth 2.0 Authorization Code + PKCE and Client Credentials flows
- Users, roles, groups, service accounts and per-client permission allowlists
- TOTP and WebAuthn/FIDO2 multi-factor authentication, step-up and device trust
- Argon2id password hashing, password policy and breach checks
- Append-only daily JSONL audit files plus queryable audit APIs
- Liveness and readiness endpoints; SQLite storage, no external database

## Run the container image

The image is published for `linux/amd64` and `linux/arm64` with build provenance.
It runs as the unprivileged `node` user, keeps all state in the `/data` volume
(`/data/iam`), listens on `0.0.0.0:4200` inside the container, and has a readiness
health check. Its entry point is the server CLI, so the commands under
[Commands](#commands) are passed as arguments to `docker run`. It needs Redis 7 or
later (queues, rate limiting, WebAuthn ceremonies); the database is SQLite inside
`/data`.

This example runs Oathweave and a password-protected Redis on a private Docker
network and publishes Oathweave on loopback only:

```bash
# 1. Secrets (keep both files private)
umask 077
printf 'REDIS_PASSWORD=%s\n' "$(openssl rand -hex 32)" > redis.env
. ./redis.env
cat > iam.env <<EOF
HIVE_AUTO_MIGRATE=true
COOKIE_SECRET=$(openssl rand -hex 32)
IAM_AGENT_SECRET=$(openssl rand -hex 32)
SEED_ADMIN_PASSWORD=$(openssl rand -base64 24)
REDIS_URL=redis://:$REDIS_PASSWORD@oathweave-redis:6379
HIVE_HEALTH_URL=http://localhost:4200/api/v1/health/ready
EOF

# 2. Redis
docker network create oathweave
docker run -d --name oathweave-redis --network oathweave --env-file redis.env \
  -v oathweave-redis:/data redis:7.4.7-alpine \
  sh -c 'exec redis-server --requirepass "$REDIS_PASSWORD" --appendonly yes'

# 3. Check, then start
docker run --rm --network oathweave --env-file iam.env ghcr.io/cheftaco/oathweave:2.0.1 check
docker run -d --name oathweave --network oathweave -p 127.0.0.1:4200:4200 \
  -v oathweave-data:/data --env-file iam.env ghcr.io/cheftaco/oathweave:2.0.1

# 4. Once it reports healthy
curl http://127.0.0.1:4200/api/v1/health/ready
curl http://127.0.0.1:4200/api/v1/oauth/.well-known/openid-configuration
```

This serves plain HTTP, so keep it on loopback or behind a TLS-terminating reverse
proxy. `HIVE_HEALTH_URL` points the image's health check at that plain HTTP
listener; its default is HTTPS. To serve HTTPS directly, mount the certificate and
key read-only under `/config`, set `TLS_CERT_PATH` and `TLS_KEY_PATH` (see
[TLS](#tls)) and drop the `HIVE_HEALTH_URL` override. `HIVE_AUTO_MIGRATE=true` lets
this first start create and migrate the database; see the migration notes below
before you keep it for later starts.

On the first start the server:

1. creates its data directory, `${HIVE_HOME:-~/.hive}/iam` (mode 0700; `/data/iam`
   in the image), holding
   `iam.db` (SQLite), `keys/` and `audit-logs/`;
2. generates a 4096-bit RS256 signing key pair in `keys/` unless you configured
   `JWT_PRIVATE_KEY_PATH` and `JWT_PUBLIC_KEY_PATH`;
3. applies the database migrations;
4. creates the built-in roles, the initial `SUPER_ADMIN` account and the
   built-in `hive` and `hive-router` OIDC clients.

Later starts refuse pending migrations unless `HIVE_AUTO_MIGRATE=true`. Explicit migration
never provisions accounts or signing keys. Backups include SQLite, scoped Redis and protected
files; missing existing databases or signing keys must be restored rather than regenerated.

## First admin account

The initial administrator is provisioned only for a new database. An existing empty database
is never reseeded automatically:

| Variable | Default | Notes |
| --- | --- | --- |
| `SEED_ADMIN_USERNAME` | `admin` | Log in with the username or the email |
| `SEED_ADMIN_EMAIL` | `admin@iam.local` | |
| `SEED_ADMIN_PASSWORD` | generated | At least 16 characters |

If `SEED_ADMIN_PASSWORD` (or `SEED_HIVE_CLIENT_SECRET` /
`SEED_HIVE_ROUTER_CLIENT_SECRET`) is unset, a random value is generated and
written to `initial-credentials.env` (mode 0600) next to the database
(`/data/iam/initial-credentials.env` in the container's volume). Values
are never printed to the log. Store them, change the password after the first
login, then delete the file. These variables are ignored once the account and
clients exist; changing them later changes nothing.

Log in through the API:

```bash
curl -X POST http://127.0.0.1:4200/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<SEED_ADMIN_PASSWORD>"}'
```

Lost the password? Run
`IAM_RESET_PASSWORD='<new password>' hive-iam-server reset-admin --env-file iam.env`.

## Configuration

Configuration comes from environment variables, optionally loaded from
`--env-file <path>` (variables already set in the environment win). An empty
value (`NAME=`) counts as unset. Relative paths resolve against the current
directory; prefer absolute paths.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `COOKIE_SECRET` | yes | | Session cookie secret, 32+ characters |
| `IAM_AGENT_SECRET` | yes | | Agent audit-ingest secret, 16+ characters |
| `PORT` | | `4200` | Listen port |
| `HOST` | | `127.0.0.1` | Listen address; `0.0.0.0` for remote access |
| `REDIS_URL` | | `redis://localhost:6379` | `redis://:PASSWORD@host:6379` for an authenticated Redis |
| `JWT_ISSUER` | | `hive-iam` | Token issuer; Hive Router expects `hive-iam` |
| `CORS_ORIGIN` | | `https://localhost` | Comma-separated browser origins, usually the Hive console URL |
| `SEED_HIVE_PUBLIC_URL` | | | Public Hive console URL, e.g. `https://hive.example.com`; sets the built-in clients' redirect URIs on first start |
| `SEED_HIVE_ROUTER_CLIENT_SECRET` | | generated | `hive-router` client secret; give Hive Router the same value as `HIVE_ROUTER_IAM_CLIENT_SECRET` |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | | | Serve HTTPS with these PEM files |
| `HIVE_HOME` | | `~/.hive` | Hive base directory |
| `IAM_DATA_DIR` | | `$HIVE_HOME/iam` | IAM data directory |
| `DATABASE_URL` | | `file:$IAM_DATA_DIR/iam.db` | SQLite database file |
| `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` | | `$IAM_DATA_DIR/keys/iam-*.pem` | RS256 signing key pair |
| `AUDIT_LOG_DIR` | | `$IAM_DATA_DIR/audit-logs` | Daily JSONL audit files |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` | | `localhost` / `https://localhost` | WebAuthn relying party, e.g. `hive.example.com` / `https://hive.example.com` |
| `TRUSTED_PROXY_IPS` | | | Socket peers allowed to send `X-Forwarded-For` (your reverse proxy) |

`hive-iam-server env-schema` prints the full list as JSON. Further options
(token lifetimes, rate limits, previous signing keys for rotation,
`IAM_MACHINE_CLIENT_POLICIES`) are described in
[`.env.example`](.env.example).

A missing or invalid setting, or an unreachable Redis, stops the server with a
single line naming the variable or dependency and the fix, and exit code 1.

## TLS

Without `TLS_CERT_PATH` and `TLS_KEY_PATH` the server speaks plain HTTP. That is
fine on loopback or behind a TLS-terminating reverse proxy (set
`TRUSTED_PROXY_IPS` to the proxy's address). To serve HTTPS directly, point both
variables at PEM files; `check` verifies that they exist, match, and have not
expired, and `start` refuses to fall back to HTTP when they are configured but
unusable.

```bash
TLS_CERT_PATH=/etc/hive-iam/tls/server.crt
TLS_KEY_PATH=/etc/hive-iam/tls/server.key
HOST=0.0.0.0
```

## Commands

The CLI is installed as `oathweave` and, for compatibility, `hive-iam-server`. In the
container image it is the entry point: pass the command after the image name, for
example `docker run --rm --network oathweave -v oathweave-data:/data --env-file iam.env ghcr.io/cheftaco/oathweave:2.0.1 migrate --plan`.

```text
hive-iam-server [start]   Start the server; startup migration requires explicit opt-in
hive-iam-server migrate   Back up and apply schema migrations; --plan is read-only
hive-iam-server check     Validate config, TLS, data directory, signing keys and Redis
hive-iam-server env-schema  Print the environment variables as JSON
hive-iam-server reset-admin Reset the admin password from IAM_RESET_PASSWORD
Options: --env-file <path> (repeatable), --no-migrate, --relax-auth-limits, --help, --version
```

`check` writes nothing and starts no listeners; it exits 0 when everything is
usable and 1 otherwise, so it works as a pre-start gate. `start --no-migrate`
refuses to start while migrations are pending, for operators who migrate as a
separate step.

`start --relax-auth-limits`, or `RELAX_AUTH_LIMITS=true` for containers, is for
testing only. Sign-in, MFA, passkey and step-up throttles stay enabled with a
ceiling of 10000 attempts per window, and failed passwords or MFA codes neither
count against an account nor lock it. Failure locks already on an account are
ignored while the mode is on; administrator locks, the password recovery
throttles and all credential checks still apply. Nothing is written to the
stored password policy or to accounts, so removing the flag restores normal
behaviour on the next start. The server prints a warning at startup, and every
`/api/v1/health` response reports the mode in the public `authLimitsRelaxed`
boolean.

## Docker

Release images are described in [Run the container image](#run-the-container-image).
To build one yourself from a clone, run `docker build -t oathweave:local .` from the
repository root; the build uses the root [`Dockerfile`](../../Dockerfile) and this
source, not an npm package.

[`docker/compose.yml`](docker/compose.yml) is the Compose example from the legacy 1.x
line. It builds or pulls `ghcr.io/cheftaco/hive-iam-server` and does not run
Oathweave 2.x.

## Health

- `GET /api/v1/health/live`: process liveness, no dependencies
- `GET /api/v1/health/ready`: SQLite and Redis readiness (503 when degraded)
- `GET /api/v1/health/dependencies`: per-dependency detail

## API areas

`/api/v1/auth`, `/api/v1/mfa/webauthn`, `/api/v1/users`, `/api/v1/roles`,
`/api/v1/groups`, `/api/v1/service-accounts`, `/api/v1/clients`,
`/api/v1/tokens`, `/api/v1/sessions`, `/api/v1/system-users`,
`/api/v1/devices`, `/api/v1/password-policy`, `/api/v1/audit`,
`/api/v1/oauth/*` (including `/.well-known/openid-configuration` and `/jwks`).
The OpenAPI document is served at `/api/docs/openapi.json`, with Swagger UI at
`/api/docs`.

Services that trust Hive IAM tokens can verify them locally with
[`@hivemagnus/hive-iam-sdk`](https://www.npmjs.com/package/@hivemagnus/hive-iam-sdk).

## Development

From a clone of the repository:

```bash
npm ci
bash scripts/generate-keys.sh
cd apps/iam-core
cp .env.example .env        # then replace every change_me value
npm run db:migrate
npm run db:seed
npm run dev
```

```bash
npm run typecheck
npm test
npm run build      # also compiles the CLI (dist/cli.js) and the seed (dist/prisma)
npm run db:generate  # after changing prisma/schema.prisma
```

## Production deploy (repository maintainers)

The repository's own systemd deploy does not use the CLI. From the workspace
root:

```bash
bash scripts/deploy-iam-core.sh
```

It installs to `/opt/hive-iam`, runs `node dist/index.js` under the `hive-iam`
unit with an explicit `.env`, migrates with `prisma migrate deploy` and seeds
through `scripts/run-db-release-gate.sh`. In the consolidated Hive deploy, use
the root `npm run deploy` whenever possible so Memory, IAM, and Router are
updated in order. IAM deploys preserve existing secrets and bootstrap
`SEED_HIVE_ROUTER_CLIENT_SECRET` only on first install. An existing host with no
recoverable Router secret fails deployment instead of silently replacing the
credential hash.

The seed itself never invents a confidential-client credential and never
rotates an existing Argon2 hash; first-install values come from the deploy
script (or, for npm installs, from the CLI's first-start bootstrap described
above). Rotate an existing client only with authenticated
`POST /api/v1/clients/:id/rotate-secret`; this produces a
`client.secret_rotated` audit event and requires a replacement secret of at
least 32 characters.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Managed upgrades

Use `hive upgrade --dry-run`, then `hive upgrade` for the enrolled release bundle. This server's
`upgrade` and `rollback` commands delegate to the same owner-run launcher. `migrate --plan --json`
is read-only; migration requires a verified backup. Set `HIVE_AUTO_MIGRATE=true` explicitly for
startup migrations outside a managed install. Slow or one-way automatic migrations are refused.
`check --json` reports configuration without initializing state. No upgrade rotates signing keys
or reseeds existing accounts. See [UPGRADING.md](https://github.com/ChefTaco/hive/blob/main/UPGRADING.md)
for adoption, compatibility, recovery, update notices and container controls.
