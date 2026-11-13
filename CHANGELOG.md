# Changelog

## [2.3.0] - 2026-11-13

**Upgrade notes.** Two changes can need configuration before upgrading; both are described under
Security below. Confidential clients must now send their client secret when exchanging an
authorization code, and deployments behind several proxy tiers must list every tier in
`TRUSTED_PROXY_IPS`. Suite browser clients and single-proxy deployments need no change.

### Security

- **Authorization-code exchange is bound to the client.** `POST /oauth/token` with
  `grant_type=authorization_code` now requires a confidential client to authenticate with its
  client secret (`client_secret` in the body, or HTTP Basic). Before this the secret was optional,
  and a code issued without a PKCE challenge could be redeemed by anyone who obtained it. A
  confidential client that used PKCE must send both its secret and the `code_verifier`. A public
  client must have started the flow with an S256 `code_challenge` (already required by
  `/oauth/authorize`) and a code without one is refused. Missing or wrong client credentials, and an
  unknown or inactive `client_id`, answer `401 invalid_client`; PKCE failures stay
  `400 invalid_grant`. A refused exchange does not consume the code.

  **Upgrade note.** Suite browser clients (`hivexui-*`, public, S256 PKCE) and callers that
  already send their secret (Emberpath's `hive-router` sign-in) are unaffected. A confidential
  client that exchanged codes without sending its secret must now send it: for the Magnus dashboard
  set `HIVE_OAUTH_CLIENT_SECRET`, or register that application as a public client instead. A
  confidential client that has no secret hash can no longer exchange codes; give it one with
  `POST /clients/{id}/rotate-secret`. To find the clients concerned, list the clients with
  `clientType: "confidential"` and the `authorization_code` grant and check that each application
  is configured with its secret.
- **The client address can no longer be chosen by the caller.** With `TRUSTED_PROXY_IPS` set, the
  leftmost `X-Forwarded-For` entry was used. A reverse proxy appends to that header, so a caller
  who sent its own `X-Forwarded-For` was rate limited, matched against IP allowlists and audited
  under the address it chose. The header is now read from the right, skipping trusted proxies, and
  the first address that is not a trusted proxy is the client; values that are not IP addresses are
  never returned. `TRUSTED_PROXY_IPS` keeps its name and format.

  **Upgrade note.** A deployment with one proxy that sends a single address (the suite ingress)
  sees no change. A deployment with several proxy tiers must list every tier in
  `TRUSTED_PROXY_IPS`: an unlisted outer proxy is now taken to be the client, where before the
  leftmost (spoofable) entry was.
- A refresh token no longer rotates once its session is revoked, and an administrator password reset
  (`PATCH /users/{id}` with a password, `POST /users/{id}/rotate-password`) now revokes the account's
  refresh tokens together with its sessions.
- A refresh token that was not issued to a client never takes a `client_id` from the refresh request,
  so the request cannot choose the `clientId`, audience or issuer of the new access token.
- Creating a sign-in (`authorization_code`) client, like changing one, requires `SUPER_ADMIN`.
- SDK: `IamVerifier.hasPermission` evaluates each principal's own permissions; results are no longer
  cached by subject across tokens.

### Fixed

- `DELETE /sessions/{id}` answers 404 for an unknown session instead of 500, and revoking a session
  again keeps its original revocation record.
- `POST /oauth/token` answers a malformed JSON body with `invalid_request` instead of 500.

## [2.2.0] - 2026-11-12

- Admit the explicit Embermend browser audience in fresh suite bootstrap with resource-specific permission ceilings.
- Pin TypeScript 6.0.3 across identity, SDK and release tooling; enable exact optional typing and explicit Node types. Omit unavailable persistence/output fields while preserving existing values on partial updates.

## [2.1.2] - 2026-11-11

- Refuse native deployments and service restarts on Node.js below the package security minimum before changing remote state.
- Require patched Node.js 24.22.3 or 26.13.1, and refresh build and runtime image pins for upstream TLS and HTTP/2 security fixes.
- Upgrade Hono to 4.13.18 to bound request-body memory independently of transfer chunk count (GHSA-39q9-qp46-w8xg).

## [2.1.1] - 2026-11-10

### Security

- Run containers on a pinned, maintained Node 26 runtime with patched system libraries.
- Replace the embedded SQLite driver with `@photostructure/sqlite` 3.3.1 (SQLite 3.54.1); retain existing databases, transaction ownership and recovery checks. Supported Linux x64 and arm64 installs include Node-API binaries and require no compiler or dependency install scripts.
- Keep Prisma query conversion and error handling in a licensed adapter for the patched SQLite driver; release failed transaction acquisitions without disturbing another transaction.

## 2.1.0 - 2026-11-08

### Added

- `IAM_MACHINE_CLIENT_POLICIES` takes an optional `"issuer":"browser"` per client. That client's
  client_credentials tokens then carry `IAM_BROWSER_ISSUER` instead of `JWT_ISSUER`, so a resource
  that verifies people on the browser issuer can verify the service on the same issuer. Startup
  requires an HTTPS `IAM_BROWSER_ISSUER` for such a policy, and a token of that client on any other
  issuer is refused. Policies without it are unchanged.
- The suite bootstrap accepts the Ardent Project Studio browser client (audience `ardentstudio`,
  `ardentstudio:` permissions).

## 2.0.4 - 2026-11-07

### Security

- Pin Hono 4.13.16 and `@hono/node-server` 2.1.6 across workspace and standalone locks, addressing GHSA-46wx-v44x-9hh2 and GHSA-jpvv-r467-5p4w. Keep the SimpleWebAuthn 14.1.0 passkey fix. Test cross-origin `text/ping` rejection and raw backslash rejection at the HTTP adapter.

## 2.0.3 - 2026-11-07

### Security

- `@simplewebauthn/server` 14.1.0 (from 13.3.2), which fixes GHSA-2g3p-m8c9-hhwh: certificate
  revocation lists are now processed only for attestation certificates that chain to a trusted
  anchor. Oathweave requests no attestation, but a registration response can still carry an
  attestation certificate chain. SimpleWebAuthn 14 requires Node.js 22 or later; the image runs
  Node.js 24.

## 2.0.2 - 2026-11-06

### Added

- Installation-owned machine clients. `IAM_MACHINE_CLIENT_SECRETS` maps machine client
  IDs from `IAM_MACHINE_CLIENT_POLICIES` to their secrets. Every start creates a listed
  client that does not exist yet, as a confidential client limited to the client
  credentials grant, and keeps its stored Argon2id hash equal to the configured secret,
  so a product-to-product credential exists and rotates without manual registration.
  Each listed client needs a policy, an administrator's deactivation is kept, and an
  existing registration of another kind stops startup instead of being converted.

### Changed

- Startup validation now checks `IAM_MACHINE_CLIENT_POLICIES` together with the secrets,
  so an invalid policy stops startup with one configuration error that names the
  variable, instead of failing when the token service loads.

## 2.0.1 - 2026-11-05

### Security

- Remove npm, npx, corepack and yarn from the runtime image, and purge apt and libapt-pkg6.0 (dpkg and its package database stay). The server and its CLI run on node alone. This removes the image's fixable HIGH findings: npm's bundled brace-expansion 5.0.9 (CVE-2026-102276, CVE-2026-102278) and undici 6.28.0 (CVE-2026-19534, CVE-2026-87018, CVE-2026-109383, CVE-2026-109869), and apt 2.6.1 (CVE-2026-109518).
- Trivy 0.70.0 reports no fixable HIGH or CRITICAL findings in the image. These Debian 12 findings have no fix available yet and remain: zlib1g CVE-2023-45853 (CRITICAL) and CVE-2026-76844, ncurses CVE-2025-69720, libsystemd0/libudev1 CVE-2026-16742, gzip CVE-2026-41992, util-linux CVE-2026-53613, CVE-2026-53615 and CVE-2026-78410, libacl1 CVE-2026-54369, and perl-base CVE-2026-9538.

## 2.0.0 - 2026-11-05

- Add `start --relax-auth-limits` and `RELAX_AUTH_LIMITS` for testing. Sign-in, MFA, passkey and step-up throttles rise to 10000 attempts per window and failed attempts stop locking accounts, at runtime only. Health responses report `authLimitsRelaxed`, and startup prints a warning. Behaviour without the flag is unchanged.

- Add explicitly selected public-browser OIDC discovery with a configured interactive authorization portal and API prefix on the browser issuer origin. Reject invalid configuration and unregistered/inactive/confidential selections without changing native discovery.

- Export standalone browser-safe identity, enrollment and authentication validators from the owning product, preserving request refinements and native response envelopes. Document actual administration response contracts and verify export drift.

- Preserve independent sign-ins behind a shared IP/browser fingerprint. Session
  revocation requires explicit session or user selection; the legacy heuristic
  cleanup endpoint returns a migration message without invalidating credentials.

- Preserve native DateTime storage compatibility for atomic enrollment credentials and reject expired ISO or legacy numeric identities before rotation.

- Move technical identity enrollment coordination into Oathweave with recent-session authorization, short-lived resource delegation, durable leases and product-owned idempotent credential receipts.
- Add explicit source-preserving offline adoption of legacy enrollment ownership, immutable product IDs, deadlines, encrypted receipts and recovery provenance. Independent installations and unknown legacy outcomes cannot be silently combined or replayed.


### Ecosystem extraction

- Make first-start seeding atomic and permit interrupted initialization only with
  its protected receipt and unchanged seed inputs. Optional fresh-suite bootstrap
  registers explicit public clients and resource grants without modifying existing
  identity stores.
Register configured suite public clients through the authorized client API using
their stable browser-policy identifiers. Existing and native client identifiers
remain unchanged; no client secret is required for PKCE browser clients.

Independent identity product snapshot, PKCE browser SSO, resource permission ceilings, session-bound codes and a separate HTTPS browser issuer. Native issuers and clients are retained. Full browser and migration acceptance remain pending.

Browser login returns a secure SSO cookie and public profile without native bearer or refresh credentials; native client login remains available. The API snapshot describes both modes. Containers bind their service listener explicitly.

- Complete browser consent, POST passkey challenges, single-use MFA, recent-session step-up, and protected recovery delivery with atomic reset-token consumption.
