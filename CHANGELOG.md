# Changelog

- Preserve native DateTime storage compatibility for atomic enrollment credentials and reject expired ISO or legacy numeric identities before rotation.

## Unreleased

- Move technical identity enrollment coordination into Oathweave with recent-session authorization, short-lived resource delegation, durable leases and product-owned idempotent credential receipts.
- Add explicit source-preserving offline adoption of legacy enrollment ownership, immutable product IDs, deadlines, encrypted receipts and recovery provenance. Independent installations and unknown legacy outcomes cannot be silently combined or replayed.


## Unreleased ecosystem extraction

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
