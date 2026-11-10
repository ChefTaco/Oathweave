# Browser identity and recovery

Fresh suite installations may supply `OATHWEAVE_SUITE_BOOTSTRAP_FILE`, an absolute,
server-owned mode-0600 JSON file. Its version-1 contract contains a preallocated
`adminId` and `clients` with stable `hivexui-*` IDs, resource audiences, explicit
permissions, exact `redirectUris` and `firstParty` flags. Client permissions must
match `IAM_BROWSER_CLIENT_POLICIES` and belong to their resource namespace. The
file must include an Oathweave client; all clients use the same console callback
origin. The initial administrator receives the union of these explicit grants in
the `SUITE_ADMIN` role. There are no wildcard grants or public client secrets.

This contract is consumed only during first-start seeding of an empty store.
Existing installations use the authorized APIs and reviewed account links.
All seed records commit together. A protected `.bootstrap-pending.json` receipt
binds interrupted first initialization to the same database and seed inputs;
retries preserve the generated initial credentials and signing keys. Existing
empty databases without that receipt require recovery. `npm run test:bootstrap`
kills a disposable seed, proves transaction rollback, resumes it, checks stable
credentials and IDs, and refuses direct suite seeding of a populated store.

Register HiveXUI public clients through the authorized clients API with exact
HTTPS callback URIs, S256 PKCE, an explicit audience and least-privilege browser
policy. Existing client IDs and native issuer URLs remain unchanged. Non-first-party
browser clients return `CONSENT_REQUIRED` before creating a code; repeat the same
bound request with `consent: "approve"` only after the user reviews access.
Declining never creates a code. Access tokens stay in browser memory and expire
within 15 minutes; the server-owned HttpOnly SSO session supplies replacements.

Set `WEBAUTHN_RP_ID` to the console's hostname and `WEBAUTHN_RP_ORIGIN` to its exact
HTTPS origin, including its port. Keep existing RP configuration stable for existing
passkeys. Login requires the password and an enabled second factor. Browser passkey
options use POST with the short-lived MFA challenge in the body; native GET remains
available for compatibility. Challenges are single-use, bound to password version,
user, ceremony and session, and expire within five minutes. Password replacement
invalidates outstanding MFA challenges. Earlier double-encoded passkey IDs are
recognized using the original record's public key, without rewriting IDs or linking
accounts. New passkeys store the credential ID directly.

Self-service authentication controls use the Oathweave audience. Factor changes
require an interactive authentication within 15 minutes. A `STEP_UP_REQUIRED`
response asks the user to verify their password and an enabled factor; passkey-only
MFA cannot fall back to password alone. The console never automatically replays a
rejected durable operation after step-up. Replacement resource tokens carry the
new authentication time. Removing TOTP preserves registered passkeys. Recovery
codes can be explicitly replaced and are shown once; old codes stop working.

## Recovery delivery

Set `IAM_RECOVERY_OUTBOX_DIRECTORY` to a dedicated, server-owned absolute directory
with mode 0700, on persistent product storage. The service creates mode-0600 JSON
receipts containing the recipient, expiring one-use recovery code and expiry time.
Connect the operator's trusted notification service to this private outbox; it must
deliver instructions through the user's verified out-of-band channel and remove
receipts after delivery or expiry. Do not expose the directory through ingress,
audit APIs, the console, static assets or a public log collector. Restrict backups
as secrets. No delivery consumer or SMTP service is silently installed.

Without a configured usable outbox, recovery returns `RECOVERY_UNAVAILABLE` for
every address before account lookup. With delivery configured, known and unknown
addresses receive the same public response. Raw recovery codes never appear in
API responses or audit events. The browser accepts the delivered code in a password
field; it does not store it or put it in a URL. Reset tokens are claimed atomically
with the password change and revocation of sessions, refresh tokens and pending
authorization codes. Expired accounts stay blocked until an approved recovery is
completed; migration rehearsals never reset existing passwords or weaken policy.

If private delivery fails after lookup, the undelivered token is invalidated and
the public response remains generic. Monitor the failure audit outcome and the
trusted delivery consumer independently; a successful request is not a delivery
receipt. Shared console ingress must keep the SSO and native refresh cookies
exclusive to Oathweave and prevent resource APIs from setting identity cookies.

## Embermend resource registration

Fresh suite bootstrap accepts the `embermend` audience and the public
`hivexui-embermend` client. Its explicit permissions use the `embermend:` prefix
and must match the operator-owned `IAM_BROWSER_CLIENT_POLICIES` ceiling. Grants
for another product or wildcard permissions are rejected. This does not change
existing client registrations or infer new authority for existing accounts.

Embermend separately maps each authenticated subject to its installation,
application and target scope. Preparation, provider writing, approval, merge and
deployment are separate product permissions. Coordinator machine clients should
receive only their configured coordination permissions; they cannot approve
their own work or edit standing policy.
