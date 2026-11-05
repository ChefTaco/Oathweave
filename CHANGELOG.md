# Changelog

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
