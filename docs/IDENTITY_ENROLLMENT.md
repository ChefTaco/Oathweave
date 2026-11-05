# Technical identity enrollment

Oathweave coordinates explicitly scoped technical identities through authenticated
product APIs. Emberpath owns native model keys and HiveMem owns native agent
credentials, generation revocation and workspace membership. Coordination does
not install an inference runtime, download a model, change host accounts, or
execute a host deployment.

Enable coordination only after all three products have their candidate migrations
and contracts installed. The single-installation configuration remains supported:

```dotenv
IAM_ENROLLMENT_INSTALLATION_ID=example-installation
IAM_BROWSER_ISSUER=https://identity.example.com
IAM_ENROLLMENT_PRODUCTS_JSON={"emberpath":{"url":"https://models.example.com/api","caFile":"/config/authority.pem"},"hivemem":{"url":"https://memory.example.com/v1","caFile":"/config/authority.pem"}}
```

One authority can coordinate multiple independent installation namespaces instead.
Set `IAM_ENROLLMENT_INSTALLATIONS_JSON` to an object keyed by installation ID;
each value has `products` (the same endpoint object shown above) and a nonempty
`operatorSubjects` array of explicitly authorized subjects on this authority.
Do not combine this setting with the single-installation settings. The same
product API endpoint cannot alias two independent installation namespaces.
Only authorized namespace IDs are returned by
`GET /api/v1/enrollments/installations`; endpoint configuration stays server-owned.
Every inventory, mutation and receipt request accepts `?installationId=ID`, and
omitting it is rejected when multiple installations are configured. HiveXUI's
optional public `enrollmentInstallationId` selects its installation; its selector
can switch only to an explicitly authorized namespace. Operation IDs, deep links,
leases, immutable policies and encrypted receipts remain scoped to that selection.

The URLs are complete API prefixes. A suite ingress uses `/api/emberpath` and
`/api/hivemem`; direct product listeners use `/api` and `/v1`. The coordinator
appends `/client-keys/operations/{id}` and `/actor-credentials/{id}` respectively.
`caFile` is optional when the normal platform trust store verifies the certificate.
Cross-host endpoints must be explicit HTTPS URLs with verified hostnames. Docker
service names work only inside the same host's networks. No endpoint credential
or administrator secret belongs in this JSON or in HiveXUI runtime configuration.
When configuration is absent, the API returns an explicit unavailable state.

`POST /api/v1/enrollments` requires a recent interactive session and
`iam:sa:write`. It accepts a stable agent ID, display name, native IAM client ID,
explicit role IDs, non-admin Memory scopes, one existing workspace and a lifetime
of 1–720 hours. The first request fixes the policy, owner and absolute credential
deadline; an unchanged retry resumes the same operation. Changing a label,
permission, lifetime or owner requires an explicitly reviewed new enrollment.
Existing role-assignment privilege guards apply. Creating or adding a member to
an archived or inaccessible workspace is refused by HiveMem. Workspaces are
managed through HiveMem's own API before enrollment.

The server issues a dedicated `oathweave-enrollment` delegation token for each
receiving product. This identity is server-owned, is not a registered public
client, and cannot mutate Oathweave APIs. Tokens carry the operator's subject and
live session, an exact resource audience, a 60-second lifetime and only the
operation's needed permissions. Current database grants are checked at issuance;
a Memory product-admin grant can be downscoped into explicit agent permissions.
The issued delegation never carries `admin:all`. Every receiver independently
verifies issuer, signature, audience, lifetime, session revocation, its explicit
issuer/subject-to-product account link and authorization. No email matching or
browser shared administrator credentials are involved.

The SQLite journal and leases live in Oathweave's existing database, keyed by installation namespace plus the unchanged public actor/operation ID. The same actor ID on separate installations never binds their product records or receipts. Native IAM
key changes and encrypted recovery receipts commit in the same transaction.
Emberpath and HiveMem atomically persist each native key/token change together
with their encrypted replay receipt. Retrying a remote unknown outcome uses the
same product operation ID and exact request, so it recovers the original
credential instead of issuing a replacement. Receipt storage failure rolls the
mutation back, or fails closed as an indeterminate persistence outcome.
Completed steps are never rerun. A stale lease cannot checkpoint or unlock a
successor's operation. Credential receipts expire after at most 15 minutes and
never extend the original credential deadline. Partial receipt expiry requires
explicit review or containment; it does not restart issuance automatically.

Lifecycle APIs accept an explicit operation UUID. Rotation preserves every
product ID and the original absolute deadline. Disable is explicit containment:
it invalidates earlier receipts, disables the recorded credentials, and retains
accounts, memberships, memories, key IDs and journal provenance. Acknowledgement
clears coordinator and product receipts without changing the usable credentials.
A repeated acknowledged or expired issuance returns 410 instead of issuing again.
HiveXUI displays the exact operation receipt in memory, can explicitly resume a
pending operation, and preserves operation IDs without storing bearer tokens.

## Offline legacy adoption

Keep the old Emberpath coordinator and its frontend available for recovery until
all replacement gates pass. Migration is an offline operation against separate
restored snapshots. Stop dispatchers/writers in those isolated restores, apply
Oathweave's candidate migrations, and retain the original Emberpath database,
original envelope secret, signing keys, product stores and backup manifests.
Do not run old and new coordinators as simultaneous writers during a cutover.

Create a mode-0600 JSON file owned by the operator, with these fields:

```json
{
  "installationId": "example-installation",
  "issuer": "https://identity.example.com",
  "sourceDatabase": "/opt/rehearsal/source/router.sqlite",
  "sourceSecretFile": "/opt/rehearsal/source/router-envelope.key",
  "targetDatabase": "/opt/rehearsal/identity/iam.sqlite",
  "targetReceiptSecretFile": "/opt/rehearsal/identity/cookie-secret.key",
  "ownerMappings": [
    {"legacyOwnerId": "example-legacy-owner", "issuer": "https://identity.example.com", "subject": "example-reviewed-subject"}
  ]
}
```

The secret files contain the existing raw Emberpath envelope secret and the
existing target Oathweave `COOKIE_SECRET`, respectively. They are not newly
created passwords. The target subject must already exist; ownership is never
inferred by matching names or email addresses. Every legacy owner needs an
explicit mapping. Keep every independent installation in a distinct explicit target namespace. One shared authority can own those namespaces without importing or merging their native IAM user, role or audit databases.

```bash
node apps/iam-core/dist/scripts/migrate-enrollments.js --config /opt/rehearsal/migration.json --dry-run
```

The dry run reports counts plus exact logical source and ownership-mapping
SHA-256 digests without printing credentials or account IDs. Review that private
mapping, then add `reviewedSourceDigest` and `reviewedMappingDigest` to the same
file. Apply only the exact reviewed inputs:

```bash
node apps/iam-core/dist/scripts/migrate-enrollments.js --config /opt/rehearsal/migration.json --apply
```

Source records are read-only and unchanged. Adoption preserves product IDs,
immutable policy hashes, credential deadlines, original receipt expiry, old
operation IDs, audit steps and explicit owner provenance. Encrypted receipts are
rewrapped under Oathweave's existing receipt key. Source keys and snapshots remain
required recovery evidence. Exact repeated adoption is a no-op; changed source,
changed ownership, active source leases, destination namespace collisions, reassignment of the same source snapshot to another namespace, and attempts to combine independent records within an existing namespace are rejected. Different reviewed snapshots can adopt distinct namespaces on one authority while preserving their native product IDs and separate source stores.

Partial legacy operations, malformed legacy policies, and enrollments whose recorded native IAM service identity is absent from the chosen authority remain `migration-review`. Such native identities are retained in their original owning installation; the tool does not copy native IAM accounts into the authority or substitute another subject. Their old dispatches lack
the new product replay contracts, so unknown outcomes are never automatically
replayed. Capture any still-live owned receipt, verify each native product's
recorded IDs and permissions, and explicitly contain incomplete resources before
reviewing a new enrollment. Legacy inventory-only lifecycle records without an
enrollment policy remain recovery evidence and require a reviewed explicit
policy; they are not silently converted into new actors. The protected migration
provenance retains their operation IDs for operator inspection.

Owned legacy enrollment receipts are exposed through
`GET /api/v1/enrollments/{actorId}/receipt` until their original expiry, with recent
interactive authentication and explicit write permission. Acknowledge them with
DELETE. Owned lifecycle receipts retain their original operation IDs. No migration
or candidate proof authorizes a production cutover or a production password reset.
