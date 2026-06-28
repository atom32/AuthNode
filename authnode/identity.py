from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any

from authnode.config import AuthNodeConfig, Tenant, Target, User
from authnode.jwt import encode_hs256


def claims_for_user(
    config: AuthNodeConfig,
    user: User,
    *,
    tenant: Tenant | None = None,
    audience: list[str] | tuple[str, ...] | str | None = None,
    ttl_seconds: int | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    effective_tenant = tenant or config.tenant_for(user.tenant_id or user.tenant_key)
    issued_at = int(now if now is not None else time.time())
    ttl = int(ttl_seconds or config.token_ttl_seconds)
    aud = _audience(audience, config.default_audience)
    return {
        "iss": config.issuer,
        "sub": user.user_key,
        "aud": aud,
        "iat": issued_at,
        "nbf": issued_at - 5,
        "exp": issued_at + ttl,
        "tenant_id": effective_tenant.tenant_id,
        "tenant_key": effective_tenant.tenant_key,
        "tenant": effective_tenant.tenant_key,
        "org_id": effective_tenant.tenant_id,
        "user_id": user.user_id,
        "user_key": user.user_key,
        "name": user.display_name,
        "email": user.email,
        "roles": list(user.roles),
        "groups": list(user.groups),
        "provider": user.provider,
    }


def issue_identity_token(
    config: AuthNodeConfig,
    user_key_or_id: str | None = None,
    *,
    tenant_id_or_key: str | None = None,
    audience: list[str] | tuple[str, ...] | str | None = None,
    ttl_seconds: int | None = None,
) -> tuple[str, dict[str, Any]]:
    user = config.user_for(user_key_or_id, tenant_id_or_key=tenant_id_or_key)
    tenant = config.tenant_for(tenant_id_or_key or user.tenant_id or user.tenant_key)
    claims = claims_for_user(config, user, tenant=tenant, audience=audience, ttl_seconds=ttl_seconds)
    return encode_hs256(claims, config.jwt_secret), claims


def issue_identity_token_for_user(
    config: AuthNodeConfig,
    user: User,
    *,
    tenant: Tenant,
    audience: list[str] | tuple[str, ...] | str | None = None,
    ttl_seconds: int | None = None,
) -> tuple[str, dict[str, Any]]:
    claims = claims_for_user(config, user, tenant=tenant, audience=audience, ttl_seconds=ttl_seconds)
    return encode_hs256(claims, config.jwt_secret), claims


def trusted_headers_for_user(
    config: AuthNodeConfig,
    user_key_or_id: str | None = None,
    *,
    tenant_id_or_key: str | None = None,
    target: str = "both",
) -> dict[str, str]:
    user = config.user_for(user_key_or_id, tenant_id_or_key=tenant_id_or_key)
    tenant = config.tenant_for(tenant_id_or_key or user.tenant_id or user.tenant_key)
    selected = target.strip().lower()
    headers: dict[str, str] = {}
    if selected in {"fastreact", "both"}:
        headers.update(
            {
                "X-FastReAct-User-Key": user.user_key,
                "X-FastReAct-Tenant-Key": tenant.tenant_key,
                "X-FastReAct-Subject": user.user_key,
                "X-FastReAct-Display-Name": user.display_name,
                "X-FastReAct-Email": user.email,
                "X-FastReAct-Groups": ",".join(user.groups),
                "X-FastReAct-Roles": ",".join(user.roles),
                "X-FastReAct-Auth-Provider": user.provider,
            }
        )
    if selected in {"pska", "both"}:
        headers.update(
            {
                "X-PSKA-User-Id": user.user_id,
                "X-PSKA-Tenant-Id": tenant.tenant_id,
                "X-PSKA-Subject": user.user_key,
                "X-PSKA-Display-Name": user.display_name,
                "X-PSKA-Email": user.email,
                "X-PSKA-Groups": ",".join(user.groups),
                "X-PSKA-Roles": ",".join(user.roles),
                "X-PSKA-Auth-Provider": user.provider,
            }
        )
    return {key: value for key, value in headers.items() if value}


def outbound_headers_for_target(
    config: AuthNodeConfig,
    target: Target,
    user_key_or_id: str | None = None,
    *,
    tenant_id_or_key: str | None = None,
    mode: str | None = None,
) -> dict[str, str]:
    selected_mode = (mode or target.mode or "jwt").strip().lower()
    if selected_mode == "jwt":
        token, _claims = issue_identity_token(
            config,
            user_key_or_id,
            tenant_id_or_key=tenant_id_or_key,
            audience=_target_audience(target.name),
        )
        return {"Authorization": f"Bearer {token}"}
    if selected_mode == "trusted_headers":
        return trusted_headers_for_user(config, user_key_or_id, tenant_id_or_key=tenant_id_or_key, target=target.name)
    if selected_mode == "service_token":
        headers: dict[str, str] = {}
        if target.service_token:
            if target.name == "fastreact":
                headers["X-FastReAct-Service-Token"] = target.service_token
            elif target.name == "pska":
                headers["X-PSKA-Service-Token"] = target.service_token
            else:
                headers["Authorization"] = f"Bearer {target.service_token}"
        headers.update(trusted_headers_for_user(config, user_key_or_id, tenant_id_or_key=tenant_id_or_key, target=target.name))
        return headers
    raise ValueError(f"unsupported target auth mode: {selected_mode}")


def public_user(user: User) -> dict[str, Any]:
    return {
        "user_id": user.user_id,
        "user_key": user.user_key,
        "tenant_id": user.tenant_id,
        "tenant_key": user.tenant_key,
        "display_name": user.display_name,
        "email": user.email,
        "roles": list(user.roles),
        "groups": list(user.groups),
        "provider": user.provider,
    }


def public_tenant(tenant: Tenant) -> dict[str, str]:
    return {
        "tenant_id": tenant.tenant_id,
        "tenant_key": tenant.tenant_key,
        "name": tenant.name,
    }


def token_response(token: str, claims: dict[str, Any]) -> dict[str, Any]:
    expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc).isoformat()
    return {
        "token_type": "Bearer",
        "access_token": token,
        "expires_at": expires_at,
        "claims": claims,
    }


def _audience(value: list[str] | tuple[str, ...] | str | None, default: tuple[str, ...]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


def _target_audience(name: str) -> list[str]:
    target = name.strip().lower()
    if target in {"fastreact", "pska"}:
        return [target]
    return [target]
