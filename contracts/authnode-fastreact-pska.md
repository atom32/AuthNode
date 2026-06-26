# AuthNode, FastReAct, and PSKA Identity Contract

This contract keeps authentication and multi-tenant context consistent across
the three local services.

## Ownership

- AuthNode owns identity proof and tenant/user mapping.
- FastReAct owns workspace isolation, tool policy, MCP routing, and audit.
- PSKA owns knowledge ACLs and data-access decisions.

AuthNode answers "who is this, and which tenant are they in?" It does not grant
FastReAct workspace permissions or PSKA knowledge permissions.

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
  --fastreact-url http://127.0.0.1:8000 \
  --fastreact-chat
```

The live FastReAct check sends metadata containing `tenant_key` and
`auth_contract_check=true`; FastReAct should bind the run to the JWT-derived
identity, then apply its own workspace and policy rules.

