# Browser SSO integration

HiveXUI is a public client. Register one public client per product audience, with
an exact HTTPS redirect URI ending in `/auth/callback`, the authorization_code
grant, and an explicit first-party policy when the suite operator owns both
applications. Public clients require S256 PKCE even when first-party.

Set `IAM_BROWSER_CLIENT_POLICIES` to a protected JSON object, for example:

```json
{"hivexui-emberpath":{"audience":"emberpath","permissions":["router:providers:read"]}}
```

The permission list is a ceiling intersected with the user's current permissions.
It does not grant permissions by itself. Identity administration does not imply
product administration. Interactive browser login returns only its server-owned session and public profile;
native access/refresh credentials are removed from that response. Product access
and ID tokens expire within fifteen minutes,
and browser code exchange does not return refresh credentials.

Set `IAM_BROWSER_ISSUER=https://identity.example.com` for browser clients. The
existing `JWT_ISSUER` continues to identify native user and machine tokens.
Existing native issuers, keys, subjects and client registrations are preserved;
do not change them merely to enable suite SSO. Each receiving resource must use
the same explicit browser issuer, exact product audience and verified HTTPS
JWKS/userinfo endpoints. Resource tokens are rejected on unrelated IAM APIs.

Browser login uses the server-owned Secure/HttpOnly/SameSite=Strict
`__Host-oathweave_sso` cookie. Set `CORS_ORIGIN` to exact approved console origins.
The browser opt-in header requires a matching Origin. Login, existing MFA and
WebAuthn completion pass through this boundary. Logout revokes the server session,
which resources validate online. Bearer credentials remain in browser memory.
The state, nonce, ID-token signature and access-token hash are verified by HiveXUI.

The added authorization-code binding migration is additive, but legacy binaries
do not recognize its migration history. Rehearse storage recovery before applying
it; binary rollback alone is not accepted. Preserve existing passkey RP/origin
configuration and registrations. Full browser passkey, consent, recovery and
step-up workflow acceptance is still pending; legacy frontends remain available.

A disposable real-service acceptance test lives in Hive's
`scripts/suite/sso-roundtrip.mjs`. It starts independent local TLS/Redis/SQLite
state and proves native/browser issuer separation, PKCE, one-use codes, exact
resource HTTP read access, preserved local product identity, unauthorized-write
denial and logout revocation. It never uses production credentials.

## Interactive browser client discovery

Native discovery remains unchanged at
`GET /api/v1/oauth/.well-known/openid-configuration` without a client selection.
For an interactive relying party, explicitly select its registered public client:
`GET /api/v1/oauth/.well-known/openid-configuration?client_id=hivexui-security-console`.
The selected ID must exist in `IAM_BROWSER_CLIENT_POLICIES` and in the database as
an active public client. Empty, repeated, unknown, inactive and confidential client
selections fail without returning native metadata.

Configure all three public values for this optional discovery profile:

```dotenv
IAM_BROWSER_ISSUER=https://identity.example.com
IAM_BROWSER_AUTHORIZATION_URL=https://identity.example.com/auth/authorize
IAM_BROWSER_API_BASE_URL=https://identity.example.com/api/oathweave
```

The authorization URL is the interactive sign-in/consent portal. The API base is
the public ingress prefix serving this Oathweave API; discovery appends
`/oauth/token`, `/oauth/userinfo` and `/oauth/jwks`. Every value must be HTTPS,
without credentials, query parameters or fragments; both endpoints must share the
browser issuer's exact origin, including its port. Supplying either endpoint
requires the complete valid configuration at startup. Selecting browser discovery
without that configuration returns `503 BROWSER_DISCOVERY_UNCONFIGURED`.

Browser discovery ignores host and forwarding headers, sets `Cache-Control:
no-store`, emits no credentials/cookies or redirects, and advertises only public
Authorization Code with S256 PKCE. It does not create clients, sessions, accounts
or keys. Registration, redirect URI checks, consent and resource authorization
remain enforced separately during authorization and token exchange. No unselected
client or issuer is inferred from a request's origin.
