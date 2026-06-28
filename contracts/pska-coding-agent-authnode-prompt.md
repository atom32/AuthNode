# Prompt For PSKA Coding Agent: Use AuthNode For Identity

You are the PSKA coding agent. Implement or review PSKA authentication and
multi-tenant identity integration using AuthNode as the external identity
broker.

## Goal

PSKA must accept identity from AuthNode and use it to build PSKA request
context. AuthNode answers "who is the caller and which tenant are they in?"
PSKA remains responsible for knowledge ACLs and data-access decisions.

Do not add a PSKA password login system, registration UI, or organization admin
console for this integration.

## Local Services

AuthNode lives at:

```text
/Users/xudawei/Documents/AuthNode
```

A local user should only need:

```bash
cd /Users/xudawei/Documents/AuthNode
./start.sh
```

AuthNode listens on:

```text
http://127.0.0.1:8788
```

Useful endpoints:

```http
GET  /ready
GET  /login
POST /login
POST /v1/auth/exchange
GET  /v1/tenants
GET  /v1/users
POST /v1/token
GET  /v1/headers
ANY  /proxy/pska/{path}
```

For browser smoke tests, `GET /login` is AuthNode-owned. In local mode it shows
a tenant/username/password form; in Keycloak mode it redirects to OIDC and then
handles `GET /oidc/callback`. `GET /login?local=1` keeps the local form for dev
and E2E. PSKA must consume the returned one-time code server-side through
`POST /v1/auth/exchange`; PSKA must not build its own password database or
expose downstream JWT/service/admin tokens to browser JavaScript.

If `admin_token` is configured, `/v1/token` and `/v1/headers` require either:

```http
X-AuthNode-Admin-Token: <admin-token>
Authorization: Bearer <admin-token>
```

Do not hard-code the admin token into PSKA source code.

Keep service startup independent. PSKA's `./start.sh` or container entrypoint
must only start PSKA. It must not launch AuthNode or FastReAct, and it must not
assume those projects exist on the same filesystem. Deployment wires the
services together with environment variables, secrets, DNS/URLs, and ingress or
proxy configuration.

## Auth Modes PSKA Should Support

PSKA should support at least:

1. `PSKA_AUTH_MODE=jwt`
2. `PSKA_AUTH_MODE=trusted_headers`
3. Existing local/service-token behavior, if already present

Fail closed for unknown or malformed identity.

## JWT Contract

For JWT mode, AuthNode sends:

```http
Authorization: Bearer <jwt>
```

Verify HS256 locally using environment/config:

```bash
PSKA_AUTH_MODE=jwt
AUTHNODE_JWT_SECRET=<same secret injected into AuthNode>
PSKA_AUTH_JWT_SECRET=$AUTHNODE_JWT_SECRET
PSKA_AUTH_JWT_ISSUER=authnode.local
PSKA_AUTH_JWT_AUDIENCE=pska
PSKA_AUTH_JWT_TENANT_CLAIMS=tenant_id,tenant_key,tenant,org_id
```

Required/expected claims:

```json
{
  "iss": "authnode.local",
  "aud": ["pska"],
  "sub": "pska:user_primary",
  "tenant_id": "tenant_default",
  "tenant_key": "tenant_default",
  "tenant": "tenant_default",
  "org_id": "tenant_default",
  "user_id": "user_primary",
  "user_key": "pska:user_primary",
  "roles": ["admin"],
  "groups": ["local"],
  "email": "primary@example.test",
  "name": "Primary Local User",
  "provider": "authnode"
}
```

PSKA should normalize:

- `tenant_id`: prefer claim `tenant_id`, then `tenant_key`, `tenant`, `org_id`.
- `user_id`: prefer claim `user_id`; otherwise if `sub` or `user_key` starts
  with `pska:`, strip the `pska:` prefix.
- `subject`: keep the full `sub` or `user_key`, for example
  `pska:user_primary`.
- `roles` and `groups`: support both arrays and comma-separated strings.

Use `tenant_id` and normalized `user_id` for PSKA `RequestContext`.
Use PSKA's own ACL logic to decide whether the user can read/write knowledge.

## Trusted Header Contract

For trusted-header mode, AuthNode sends PSKA-specific headers:

```http
X-PSKA-User-Id: user_primary
X-PSKA-Tenant-Id: tenant_default
X-PSKA-Subject: pska:user_primary
X-PSKA-Display-Name: Primary Local User
X-PSKA-Email: primary@example.test
X-PSKA-Groups: local
X-PSKA-Roles: admin
X-PSKA-Auth-Provider: authnode
```

Only trust these headers behind AuthNode, a trusted gateway, or loopback-local
development. Do not trust caller-supplied identity headers from the public
internet.

## Proxy Contract

AuthNode's proxy route is:

```text
http://127.0.0.1:8788/proxy/pska/{path}
```

The proxy strips caller-supplied identity material before forwarding:

- `Authorization`
- `X-FastReAct-*`
- `X-PSKA-*`
- `X-AuthNode-*`
- hop-by-hop headers

Then it injects AuthNode-generated JWT or trusted headers for PSKA.

Use this for local smoke tests:

```bash
curl "http://127.0.0.1:8788/proxy/pska/ready?authnode_user_key=pska:user_primary&authnode_tenant_id=tenant_default"
```

## PSKA Gateway/BFF Contract

PSKA may provide a thin gateway/BFF for browser access. This gateway is allowed
to serve the built PSKA frontend, redirect unauthenticated browser requests,
consume an AuthNode browser login code or verified callback identity, store a
signed HttpOnly session cookie, and proxy API requests to PSKA.

This gateway must still treat AuthNode as the identity broker:

- The built-in `/login` page is a local/dev token-broker shim, not a PSKA
  password database, registration UI, or organization admin console.
- A production SSO/OIDC flow should use AuthNode `/login` -> Keycloak/OIDC ->
  AuthNode `/oidc/callback` -> PSKA `/auth/callback` with a one-time code. The
  browser must not receive downstream PSKA/FastReAct JWTs in URLs or
  JavaScript.
- Keycloak tenant/user mapping is AuthNode's job. Missing tenant/user claims
  must fail closed before PSKA receives a session.
- PSKA Gateway may call AuthNode `POST /v1/auth/exchange` server-side to
  exchange a one-time browser login code for an `aud=pska` JWT and claims.
- Browser JavaScript must never receive AuthNode admin tokens, PSKA service
  tokens, FastReAct service tokens, or PSKA JWTs.
- `/auth/session` may return tenant/user/profile metadata, but not bearer
  tokens.
- The gateway must strip caller-supplied `Authorization`, `X-PSKA-*`,
  `X-FastReAct-*`, `X-AuthNode-*`, cookies, and hop-by-hop headers before it
  injects AuthNode-derived PSKA JWT/trusted headers.
- PSKA still owns knowledge ACLs, tenant filtering, review governance, and
  audit semantics after the gateway has established request identity.

## Contract Checks

Offline contract check:

```bash
cd /Users/xudawei/Documents/AuthNode
PYTHONPATH=. python -m authnode contract pska:user_primary --tenant tenant_default
```

Live PSKA `/ready` check:

```bash
cd /Users/xudawei/Documents/AuthNode
PYTHONPATH=. python -m authnode contract pska:user_primary \
  --tenant tenant_default \
  --live \
  --pska-url http://127.0.0.1:8765
```

## Implementation Rules

- Do not import AuthNode internals into PSKA runtime code.
- Do not read `/Users/xudawei/Documents/AuthNode/authnode.local.json` from PSKA
  application code. Use PSKA config/env instead.
- Do not start AuthNode or FastReAct from PSKA's startup script.
- Do not store user passwords for this integration.
- Do not expose AuthNode admin tokens, PSKA service tokens, FastReAct tokens, or
  PSKA JWTs to browser JavaScript. Keep them in server-side env/config or
  HttpOnly server-managed sessions.
- Do not let missing identity silently fall back to an admin/system user.
- Do not let `tenant_key` from FastReAct replace PSKA's ACL decisions.
- Add tests for valid JWT, invalid signature, wrong issuer, wrong audience,
  expired token, trusted headers, and missing identity.
- Keep PSKA knowledge ACLs in PSKA.

## Acceptance Criteria

- AuthNode JWT with `aud=pska` creates a PSKA request context with
  `tenant_id=tenant_default`, `user_id=user_primary`, and roles/groups.
- AuthNode trusted headers create the same PSKA request context.
- Missing/invalid JWT returns 401 or equivalent authentication failure.
- Wrong tenant/user cannot bypass PSKA knowledge ACLs.
- `/proxy/pska/ready` works in local development after AuthNode and PSKA are
  started.
- PSKA gateway `/auth/session` returns only identity metadata, while proxied
  PSKA API calls receive AuthNode-derived tenant/user identity server-side.
