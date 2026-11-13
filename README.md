# Oathweave

Oathweave is the identity and access management service for the Hive:Magnus suite. It issues RS256-signed JWTs, implements OAuth 2.0 and OpenID Connect, enforces role-based access control and keeps an append-only audit trail. A companion SDK lets other services verify its tokens locally.

It is one product in the [Hive:Magnus](https://github.com/ChefTaco/hive) suite, and it also runs on its own. The [Hive installer](https://github.com/ChefTaco/hive#readme) deploys tested combinations of the suite's products.

This project was extracted from Hive with its migration history and client protocols intact. `provenance.json` records the source revision and original file hashes.

This directory is an npm workspace containing the service, the SDK, and the
operational scripts used to deploy and maintain them.

## Layout

| Path | Purpose |
| --- | --- |
| [`apps/iam-core`](apps/iam-core) | `@hivemagnus/oathweave`: the identity server and its CLI (Hono, SQLite via Prisma, Redis): auth, users, roles, groups, service accounts, clients, sessions, MFA/WebAuthn, OAuth/OIDC, audit. Released as the container image `ghcr.io/cheftaco/oathweave` |
| [`packages/iam-sdk`](packages/iam-sdk) | `@hivemagnus/oathweave-sdk`: JWT verification and RBAC middleware for Node.js and Hono, published on npm as [`@hivemagnus/hive-iam-sdk`](https://www.npmjs.com/package/@hivemagnus/hive-iam-sdk) |
| [`scripts`](scripts) | Key generation, deployment, lockout reset, and end-to-end smoke tests |
| [`docs`](docs) | [Architecture notes](docs/APP_ARCHITECTURE_IAM.md) |

## Features

- RS256 access tokens with rotating refresh tokens and a JWKS endpoint
- OAuth 2.0 Authorization Code + PKCE and Client Credentials flows, OIDC discovery
- Users, roles, groups, service accounts, and per-client permission allowlists
- TOTP and WebAuthn/FIDO2 multi-factor authentication, step-up, device trust
- Argon2id password hashing, password policy, and breach checks
- Append-only daily audit log files plus queryable audit APIs
- Liveness, readiness, and dependency health endpoints

## Install

Oathweave 2.x ships only as a container image, `ghcr.io/cheftaco/oathweave`, for
`linux/amd64` and `linux/arm64`. Each release is tagged with its exact version (for
example `2.3.0`; there is no `latest` tag), and its
[GitHub release](https://github.com/ChefTaco/Oathweave/releases) records the image digest.

**With the Hive suite.** Oathweave is normally installed by `hive.sh`, the
[Hive suite controller](https://github.com/ChefTaco/hive#install-the-suite); every suite
profile includes it. The controller pins the image by digest from a signed release
manifest, writes its configuration and secrets, and runs its private Redis. Use a current signed suite release for the reviewed product and datastore pins.

**Legacy npm packages.** The npm package `@hivemagnus/hive-iam-server` and the image
`ghcr.io/cheftaco/hive-iam-server` are the legacy Hive IAM 1.x line, which predates this
repository. `npm install` and `npx` resolve that package to 1.2.2, not to Oathweave 2.x,
and `@hivemagnus/oathweave` is not published on npm. The
[Hive README](https://github.com/ChefTaco/hive#the-retired-npm-packages) describes the 1.x line.

**On its own.** Run the image with a Redis it can reach. The
[server README](apps/iam-core/README.md#run-the-container-image) has a complete
`docker run` example, the configuration reference and first-start behaviour.

## Getting Started (from source)

Requires Node.js 24 (`>=24.22.3`) or 26 (`>=26.13.1`), Redis and OpenSSL.

```bash
npm install

# Generate the RS256 signing key pair into ./certs (gitignored)
bash scripts/generate-keys.sh

cd apps/iam-core
cp .env.example .env        # then replace every change_me value
npm run db:generate
npm run db:migrate
npm run db:seed
npm run dev
```

The API listens on `PORT` (default `4200`). TLS is enabled when
`TLS_CERT_PATH` and `TLS_KEY_PATH` are set; otherwise run it behind a
TLS-terminating reverse proxy. See [`apps/iam-core/README.md`](apps/iam-core/README.md)
for the full list of environment variables.

The seed requires `SEED_ADMIN_PASSWORD`, `SEED_HIVE_CLIENT_SECRET`, and
`SEED_HIVE_ROUTER_CLIENT_SECRET` on first run. It never generates a secret and
never replaces an existing client secret hash; rotate client secrets with
`POST /api/v1/clients/:id/rotate-secret`.

## Development

From the repository root:

```bash
npm run typecheck   # all workspaces
npm test            # all workspaces
npm run build       # all workspaces
```

Workspace-specific shortcuts: `npm run iam-core:test`, `npm run iam-sdk:test`,
`npm run iam-core:build`, `npm run iam-sdk:build`.

Releases: pushing a `v*` tag runs `.github/workflows/release-image.yml`, which runs
CI, builds the image for both architectures, publishes it to
`ghcr.io/cheftaco/oathweave` with a build provenance attestation, and records the
digest in a GitHub release.

## Deployment

`scripts/deploy-iam-core.sh` builds IAM Core, uploads it over SSH, installs it
to `/opt/hive-iam`, runs migrations (and the seed on first install), installs
the root-owned JWT rotation helpers, and restarts the `hive-iam` systemd
service.

```bash
export HIVE_IAM_DEPLOY_HOST=iam-host.example.com
export HIVE_PUBLIC_URL=https://hive.example.com

bash scripts/deploy-iam-core.sh             # deploy
bash scripts/deploy-iam-core.sh --dry-run   # build and package only
bash scripts/deploy-iam-core.sh --seed      # deploy and force a re-seed
```

On a first install, `COOKIE_SECRET`, `IAM_AGENT_SECRET`, `SEED_ADMIN_PASSWORD`,
`SEED_HIVE_CLIENT_SECRET`, and `SEED_HIVE_ROUTER_CLIENT_SECRET` are taken from
the environment when set and otherwise generated with `openssl rand`. They are
stored only in the root-protected `/opt/hive-iam/.env` on the target and are
never printed. Later deploys reuse the values in that file. The script contains
no literal secret defaults and rejects supplied values that are too short.
SSH uses key or agent authentication by default
(`DEPLOY_USER`, default `deploy`; `DEPLOY_SSH_KEY` or `HIVE_IAM_DEPLOY_SSH_KEY`).
Password-based SSH is available only for bootstrapping with
`DEPLOY_ALLOW_PASSWORD=true` and `DEPLOY_PASSWORD`. Remote `sudo` runs
non-interactively unless `DEPLOY_SUDO_PASSWORD` is set. Run the script with
`--help` for the full list of options.

On the target host:

- The application tree is root-owned; the `hive-iam` runtime user can write
  only the Prisma database and audit-log directories.
- A private CA under `/var/lib/hive-iam-pki` issues a fresh 30-day TLS leaf
  certificate on each deploy; consumers trust `certs/ca-bundle.crt`.
- JWT signing keys live in an atomic, root-only keyring under
  `/var/lib/hive-iam-keyring`. Rotate them with
  `/usr/local/libexec/hive-iam/rotate-jwt-signing-key.sh`, which validates
  readiness and the live JWKS and rolls back on failure.
- Initial administrator credentials are written to a root-only file on the
  target, never to the deploy log.

### Operations

| Task | Command |
| --- | --- |
| Reset the built-in admin password | `IAM_RESET_PASSWORD=<password> npm run reset:admin` (from `/opt/hive-iam`) |
| Clear account lockouts and rate limits | `bash scripts/reset-iam-locks.sh <host>` |
| End-to-end smoke test through the Hive UI proxy | `bash scripts/test-iam-api.sh https://hive.example.com` |

## Health

- `GET /api/v1/health/live`: dependency-free liveness
- `GET /api/v1/health/ready`: SQLite and Redis readiness (used by deploy and key rotation)
- `GET /api/v1/health/dependencies`: per-dependency detail

## License

Apache-2.0. See the [LICENSE](LICENSE) file at the repository root.

Container probes use a loopback `HIVE_HEALTH_URL`. Override its port/protocol for
the selected deployment. When the service certificate uses a DNS name, set
`HIVE_HEALTH_TLS_NAME` to that name and `NODE_EXTRA_CA_CERTS` to the approved CA
bundle when needed. Probes retain certificate verification. Runtime state belongs
in `/data`; mount only product-owned protected configuration in `/config`.

Browser clients, passkeys, step-up and private recovery delivery are documented in
[the browser authentication guide](docs/BROWSER_AUTH.md). Existing production migration gates remain required.

Browser consumers use the product-owned `docs/browser-contracts.ts` candidate
artifact with its exact SHA256 and version. `npm run contracts:browser` exports
the pure Zod validators without database, server or signing dependencies;
`npm run check:browser` rejects source/export drift. The export preserves request
refinements, defaults and bounds that cannot be recovered from OpenAPI alone.
`docs/openapi.json` also describes the actual browser administration envelopes,
including existing native client mutation serialization. Publication remains a
separate release action; consumers pin reviewed immutable snapshots until then.

## Native deployment runtime checks

Source deployment checks the Node.js used by npm and `/usr/bin/node`, which the
installed systemd service uses, against the current package `engines.node` policy.
An unsupported runtime stops deployment before remote writes or service restarts.
Update the system interpreter as well as any shell-specific Node.js installation.
