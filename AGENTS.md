# Oathweave contributor instructions

Oathweave is the OAuth 2.0 / OpenID Connect identity service of the Hive:Magnus suite:
sign-in, RS256 tokens with JWKS, RBAC, MFA, service accounts and audit. It runs on its
own or under the Hive suite controller, and HiveXUI (the suite's only UI) signs in
through it. This public Apache-2.0 product is extracted from Hive. Preserve LICENSE,
NOTICE, provenance.json and immutable database migration history. Never commit secrets,
private infrastructure, databases, runtime state, local notes or real user data.
Read AGENTS.local.md when present; never copy it into tracked content.

## Layout

- `apps/iam-core`: the server and its CLI (`@hivemagnus/oathweave`; Hono, Prisma/SQLite,
  Redis). Routes in `src/routes`, config schema in `src/config/env-schema.ts`, CLI in
  `src/cli.ts` and `src/cli/`, migrations in `prisma/migrations`.
- `packages/iam-sdk`: `@hivemagnus/oathweave-sdk`, published on npm as
  `@hivemagnus/hive-iam-sdk`.
- `tooling/release`: vendored release and recovery engine. It is build tooling, not an
  import from a sibling repository. Keep existing compatibility paths until replacement
  workflow and recovery acceptance passes.
- `scripts`: deploy, key generation, smoke tests, privacy and secret scans.
- `docs`: architecture, browser auth/SSO, enrollment, `openapi.json` and the
  `browser-contracts.ts` export.

## Checks

Set up with `npm run bootstrap` (installs every workspace and the git hooks). Before
committing run the CI gates:

```bash
npm run typecheck && npm run build && npm test
npm run check:openapi && npm run check:browser
npm run scan:secrets && npm run check:private
```

After an intentional route or schema change run `npm run generate:openapi`; after a
browser route change run `npm run contracts:browser`, and commit both outputs. Hooks live
in `.githooks` (`git config core.hooksPath .githooks`); never bypass them.

## Conventions

Use strict TypeScript and runtime validation at API boundaries. Browser code must use
public API contracts and must not import backend code or infrastructure credentials.
Security behavior requires regression tests. Use Conventional Commits.

## Release path

A `v*` tag runs `.github/workflows/release-image.yml`, which builds and publishes the
container image `ghcr.io/cheftaco/oathweave` (amd64 and arm64, exact version tags, no
`latest`) and records its digest in a GitHub release. Hive's signed suite manifest pins
that digest.

## Gotchas

- `@hivemagnus/oathweave` is not published on npm. The npm package
  `@hivemagnus/hive-iam-server` is the legacy 1.x line; do not document it as current.
- The CLI applies its own defaults (`HOST=127.0.0.1`, `JWT_ISSUER=hive-iam`); `npm run dev`
  reads `src/config/env-schema.ts` defaults directly, which differ.
- `scripts/deploy-iam-core.sh` is the native systemd deploy (`/opt/hive-iam`), separate
  from the container image and the suite controller.
