# AuthNode, FastReAct, and PSKA Identity Contract

This contract keeps authentication and multi-tenant context consistent across
the three local services.

For PSKA implementation work, use
`contracts/pska-coding-agent-authnode-prompt.md` as the coding-agent prompt.

## Ownership

- AuthNode owns identity proof and tenant/user mapping. It can prove identity
  through its SQLite-backed Local IAM catalog or by adapting an external
  provider such as Keycloak/OIDC.
- FastReAct owns workspace isolation, tool policy, MCP routing, and audit.
- PSKA owns knowledge ACLs and data-access decisions.

AuthNode answers "who is this, and which tenant are they in?" It does not grant
FastReAct workspace permissions or PSKA knowledge permissions.

For browser smoke tests, AuthNode owns the login entrypoint. In Local IAM mode
it authenticates against its SQLite catalog with Argon2id password hashes and
strict membership checks; in Keycloak mode it redirects to OIDC and handles
`/oidc/callback`. In both modes it gives PSKA Gateway only a short-lived
one-time code. PSKA Gateway exchanges that code server-side and stores a
server-managed browser session.

In Keycloak mode, tenant identity must come from a verified token claim such as
`tenant_id` or `tenant_key`. Missing tenant/user claims fail closed before
AuthNode issues downstream PSKA/FastReAct credentials.

In Local IAM mode, tenant identity must come from an active membership in the
catalog. Disabled users, disabled tenants, missing memberships, and rate-limited
login attempts fail closed before downstream credentials are issued.

Local IAM administration belongs to AuthNode. The CLI and the admin-token
protected `/v1/iam/*` JSON APIs may create tenants, users, memberships, role
grants, provider account links, and audit queries. They must not mutate PSKA or
FastReAct data.

Startup remains independent: AuthNode, FastReAct, and PSKA are each started by
their own script or container entrypoint. No project start script launches or
reads another project's repository-local runtime config.

## JWT Contract

For FastReAct:

- `aud`: `fastreact`
- `sub`: FastReAct `user_key`, for example `pska:user_primary`
- `tenant_key`: FastReAct tenant key
- `tenant_id`, `tenant`, `org_id`: compatibility aliases
- `roles`, `groups`, `email`, `name`: profile metadata

For PSKA:

- `aud`: `pska`
- `sub`: the same identity subject, for example `pska:user_primary`
- `tenant_id`: PSKA tenant id
- `tenant_key`, `tenant`, `org_id`: compatibility aliases
- `roles`, `groups`, `email`, `name`: profile metadata

PSKA normalizes `pska:user_primary` to internal `user_primary` where its
`RequestContext` expects a PSKA user id. FastReAct keeps the full `user_key`.

## Trusted Header Contract

FastReAct headers:

```http
X-FastReAct-User-Key: pska:user_primary
X-FastReAct-Tenant-Key: tenant_default
X-FastReAct-Subject: pska:user_primary
X-FastReAct-Roles: admin
X-FastReAct-Groups: local
X-FastReAct-Auth-Provider: authnode
```

PSKA headers:

```http
X-PSKA-User-Id: user_primary
X-PSKA-Tenant-Id: tenant_default
X-PSKA-Subject: pska:user_primary
X-PSKA-Roles: admin
X-PSKA-Groups: local
X-PSKA-Auth-Provider: authnode
```

## Proxy Contract

`/proxy/{target}/...` must strip caller-supplied identity material before
forwarding:

- `Authorization`
- `X-FastReAct-*`
- `X-PSKA-*`
- `X-AuthNode-*`
- hop-by-hop headers

It then injects AuthNode-generated JWT or trusted headers for the selected
target.

## PSKA Gateway/BFF Contract

For browser access, PSKA can run a gateway/BFF in front of its API and built
frontend:

- The browser talks to the PSKA gateway, not directly to PSKA service auth,
  FastReAct, or AuthNode admin APIs.
- The gateway obtains `aud=pska` tokens from AuthNode server-side, either by
  exchanging a one-time browser login code at `POST /v1/auth/exchange` or by
  receiving already verified callback identity. It stores only a signed
  HttpOnly browser session and proxies PSKA API calls with AuthNode-derived
  JWT/trusted headers.
- The gateway strips caller-supplied identity headers before injecting
  `X-PSKA-Tenant-Id`, `X-PSKA-User-Id`, `X-PSKA-Subject`, roles, groups, and
  provider metadata.
- `/auth/session` may expose tenant/user metadata for UI state, but must not
  expose AuthNode admin tokens, PSKA service tokens, FastReAct tokens, or PSKA
  JWTs.
- AuthNode browser login redirects back to PSKA Gateway with a short-lived
  one-time code, not a downstream JWT in the browser URL. Production SSO should
  keep the same OIDC -> AuthNode code -> PSKA callback and BFF/session/proxy
  boundary.

## Contract Checker

Run offline checks:

```bash
python -m authnode contract pska:user_primary --tenant tenant_default
```

Run live PSKA `/ready` check:

```bash
python -m authnode contract pska:user_primary \
  --tenant tenant_default \
  --live \
  --pska-url http://127.0.0.1:8765
```

Run FastReAct `/v1/chat/completions` check only when you want an actual agent
call:

```bash
python -m authnode contract pska:user_primary \
  --tenant tenant_default \
  --live \
  --fastreact-url http://127.0.0.1:18741 \
  --fastreact-chat
```

The live FastReAct check sends metadata containing `tenant_key` and
`auth_contract_check=true`; FastReAct should bind the run to the JWT-derived
identity, then apply its own workspace and policy rules.
