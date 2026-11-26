# Security Policy

## Supported versions

Security fixes are released for the latest `2.x` version.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Report them privately through
[GitHub private vulnerability reporting](https://github.com/ChefTaco/Oathweave/security/advisories/new).
Please include:

- the affected component (Oathweave server or SDK) and version or commit
- steps to reproduce, or a proof of concept
- the impact you expect

You should get an acknowledgement within a few days. Once a fix is available, a GitHub security
advisory will credit you unless you ask not to be named.

## Hardening notes for operators

- Run every service over TLS in production, and keep admin listeners on a private network.
- Keep `.env` files, IAM signing keys, and TLS keys readable only by root or the service user.
- Rotate client secrets with `POST /api/v1/clients/:id/rotate-secret` (send no `secret` and the
  server generates one and returns it once) and JWT signing keys with the root-owned helper; see
  [apps/iam-core/README.md](apps/iam-core/README.md) and [README.md](README.md#deployment).
- Guard the `hive-router` client secret like an administrator password. A `client_credentials`
  token for it can hold `iam:users:*`, `iam:roles:write`, `iam:groups:write`, `iam:clients:write`,
  `iam:policy:write` and `iam:sessions:revoke`: whoever holds the secret can read and change every
  account, role, group and client. The model gateway's console proxy uses it on behalf of a signed-in console operator,
  whom it names in `x-hive-operator`. Oathweave refuses a write made with this token that names
  no operator (the token alone is read-only), and checks operators signed in through Oathweave
  (`authMode: "iam-oidc"`) as themselves. Operators the gateway signs in by host account
  (`authMode: "os"`) act unrestricted, so restrict who can reach that console.
