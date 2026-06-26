# AuthNode

AuthNode is a small local identity broker for FastReAct and PSKA development.
It is intentionally not a full SSO product. Its job is to provide the same
identity contract that a future SSO gateway or identity broker would provide:

- a local tenant/user catalog;
- HS256 JWTs accepted by FastReAct and PSKA;
- trusted headers accepted by FastReAct and PSKA;
- an optional local proxy that injects JWTs or trusted headers into upstream
  FastReAct and PSKA calls.

## Why this shape

FastReAct and PSKA should not each grow their own password login, org admin
console, or duplicate business ACL system. AuthNode sits at the local
development boundary:

```mermaid
flowchart LR
  User["Local user/tool"] --> AuthNode["AuthNode"]
  AuthNode -->|Authorization: Bearer HS256 JWT| FastReAct["FastReAct"]
  AuthNode -->|Authorization: Bearer HS256 JWT| PSKA["PSKA"]
  AuthNode -.->|trusted headers when needed| FastReAct
  AuthNode -.->|trusted headers when needed| PSKA
```

The important claim contract is:

- `sub`: FastReAct `user_key`, for example `pska:user_primary`;
- `tenant_key`: FastReAct tenant key;
- `tenant_id`: PSKA tenant id;
- `tenant`, `org_id`: compatibility aliases;
- `roles`, `groups`, `email`, `name`: profile metadata.

PSKA normalizes `pska:user_primary` to `user_primary` for its internal
`RequestContext.user_id`, while FastReAct keeps the full `user_key`.

## Quick start

Run AuthNode:

```bash
./start.sh
```

On first run, `./start.sh` creates `authnode.local.json` and initializes local
`jwt_secret`/`admin_token` automatically. For non-local use, inject the same JWT
secret into AuthNode, FastReAct, and PSKA through deployment secrets or
environment variables.

Print environment variables for FastReAct and PSKA:

```bash
python -m authnode env
```

Issue a token:

```bash
python -m authnode token pska:user_primary --raw
```

Generate trusted headers:

```bash
python -m authnode headers pska:user_primary --target both --curl
```

Run in the background:

```bash
./start.sh --daemon
./start.sh --status
./start.sh --stop
```

AuthNode's own `./start.sh` only starts AuthNode. FastReAct and PSKA must be
started from their own repositories or containers; no project start script
should launch another project. Runtime logs and PID files stay inside this
repository under `logs/` and `run/`.

Use the local proxy:

```bash
curl "http://127.0.0.1:8788/proxy/pska/ready?authnode_user_key=pska:user_primary"
curl "http://127.0.0.1:8788/proxy/fastreact/ready?authnode_user_key=pska:user_primary"
```

## FastReAct configuration

For JWT mode:

```bash
export FASTREACT_AUTH_MODE=jwt
export AUTHNODE_JWT_SECRET='same-secret-injected-into-authnode'
export FASTREACT_AUTH_JWT_SECRET="$AUTHNODE_JWT_SECRET"
export FASTREACT_AUTH_JWT_ISSUER='authnode.local'
export FASTREACT_AUTH_JWT_AUDIENCE='fastreact'
export FASTREACT_AUTH_JWT_TENANT_CLAIMS='tenant_key,tenant_id,tenant,org_id'
```

FastReAct JSON config can also reference the env var instead of storing the
secret directly:

```json
{
  "auth": {
    "mode": "jwt",
    "jwt_secret_env": "AUTHNODE_JWT_SECRET",
    "jwt_issuer": "authnode.local",
    "jwt_audience": "fastreact"
  }
}
```

For trusted-header mode:

```bash
export FASTREACT_AUTH_MODE=trusted_headers
```

## PSKA configuration

For JWT mode:

```bash
export PSKA_AUTH_MODE=jwt
export AUTHNODE_JWT_SECRET='same-secret-injected-into-authnode'
export PSKA_AUTH_JWT_SECRET="$AUTHNODE_JWT_SECRET"
export PSKA_AUTH_JWT_ISSUER='authnode.local'
export PSKA_AUTH_JWT_AUDIENCE='pska'
export PSKA_AUTH_JWT_TENANT_CLAIMS='tenant_id,tenant_key,tenant,org_id'
```

For trusted-header mode:

```bash
export PSKA_AUTH_MODE=trusted_headers
```

## API

- `GET /health`
- `GET /ready`
- `GET /v1/tenants`
- `GET /v1/users`
- `POST /v1/token`
- `GET /v1/headers`
- `ANY /proxy/{target}/{path}`

## Cross-project contract

The AuthNode/FastReAct/PSKA identity contract is documented in
`contracts/authnode-fastreact-pska.md`. Run the offline checker with:

For PSKA implementation work, give the PSKA coding agent this prompt:

```text
contracts/pska-coding-agent-authnode-prompt.md
```

```bash
python -m authnode contract pska:user_primary --tenant tenant_default
```

Optional live checks can call PSKA `/ready` and, when explicitly requested,
FastReAct `/v1/chat/completions`:

```bash
python -m authnode contract pska:user_primary \
  --tenant tenant_default \
  --live \
  --pska-url http://127.0.0.1:8765
```

`POST /v1/token` accepts:

```json
{
  "user_key": "pska:user_primary",
  "tenant_id": "tenant_default",
  "audience": ["fastreact", "pska"],
  "ttl_seconds": 28800
}
```

`GET /v1/headers` query parameters:

- `user_key`
- `tenant_id`
- `target`: `fastreact`, `pska`, or `both`
- `mode`: `trusted_headers` or `jwt`

If `admin_token` is configured, `/v1/token` and `/v1/headers` require either:

```http
X-AuthNode-Admin-Token: local-admin-token
Authorization: Bearer local-admin-token
```

## Strict identity mode

Local development defaults to a forgiving identity catalog: an unknown user can
be synthesized as `pska:<id>`, and an unknown tenant falls back to the default
tenant. For hardened local tests or production-like runs, enable strict mode:

```json
{
  "strict_identity": true,
  "admin_token": "local-admin-token",
  "allow_unknown_users": false,
  "allow_unknown_tenants": false
}
```

With this profile, AuthNode rejects unknown tenants and users instead of
silently creating local identities. In strict mode, `/v1/token` and
`/v1/headers` are unavailable unless `admin_token` is configured.

## Production direction

For production, replace AuthNode's local catalog and demo login surface with a
real OIDC/SAML/LDAP/customer-platform identity broker. Keep the same downstream
contract: verified JWTs or trusted headers carrying `sub`, `tenant_id`,
`tenant_key`, roles, groups, and profile metadata. PSKA remains responsible for
knowledge ACLs; FastReAct remains responsible for workspace/tool policy.
