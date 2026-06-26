from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_FILE = "authnode.local.json"
EXAMPLE_CONFIG_FILE = "authnode.example.json"


@dataclass(frozen=True, slots=True)
class Tenant:
    tenant_id: str
    tenant_key: str
    name: str = ""


@dataclass(frozen=True, slots=True)
class User:
    user_id: str
    user_key: str
    tenant_id: str
    tenant_key: str
    display_name: str = ""
    email: str = ""
    roles: tuple[str, ...] = field(default_factory=tuple)
    groups: tuple[str, ...] = field(default_factory=tuple)
    provider: str = "authnode"


@dataclass(frozen=True, slots=True)
class Target:
    name: str
    base_url: str
    mode: str = "jwt"
    service_token: str | None = None


@dataclass(frozen=True, slots=True)
class AuthNodeConfig:
    host: str = "127.0.0.1"
    port: int = 8788
    jwt_secret: str = "change-me-local-authnode-secret"
    issuer: str = "authnode.local"
    default_audience: tuple[str, ...] = ("fastreact", "pska")
    token_ttl_seconds: int = 28800
    strict_identity: bool = False
    admin_token: str | None = None
    allow_unknown_users: bool = True
    allow_unknown_tenants: bool = True
    tenants: tuple[Tenant, ...] = field(default_factory=tuple)
    users: tuple[User, ...] = field(default_factory=tuple)
    targets: dict[str, Target] = field(default_factory=dict)
    source_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, source_path: Path | None = None) -> "AuthNodeConfig":
        tenants = tuple(_tenant_from_dict(item) for item in data.get("tenants", []))
        tenant_by_id = {tenant.tenant_id: tenant for tenant in tenants}
        tenant_by_key = {tenant.tenant_key: tenant for tenant in tenants}
        users = tuple(_user_from_dict(item, tenant_by_id, tenant_by_key) for item in data.get("users", []))
        targets = {
            str(name): _target_from_dict(str(name), value)
            for name, value in dict(data.get("targets", {})).items()
        }
        default_audience = data.get("default_audience", ["fastreact", "pska"])
        strict_identity = _bool(data.get("strict_identity"), default=False)
        return cls(
            host=str(data.get("host") or "127.0.0.1"),
            port=int(data.get("port") or 8788),
            jwt_secret=str(data.get("jwt_secret") or "change-me-local-authnode-secret"),
            issuer=str(data.get("issuer") or "authnode.local"),
            default_audience=tuple(_string_list(default_audience)) or ("fastreact", "pska"),
            token_ttl_seconds=int(data.get("token_ttl_seconds") or 28800),
            strict_identity=strict_identity,
            admin_token=_optional_string(data.get("admin_token")),
            allow_unknown_users=_bool(data.get("allow_unknown_users"), default=not strict_identity),
            allow_unknown_tenants=_bool(data.get("allow_unknown_tenants"), default=not strict_identity),
            tenants=tenants,
            users=users,
            targets=targets,
            source_path=source_path,
        )

    def tenant_for(self, tenant_id_or_key: str | None) -> Tenant:
        key = (tenant_id_or_key or "").strip()
        for tenant in self.tenants:
            if tenant.tenant_id == key or tenant.tenant_key == key:
                return tenant
        if key and not self.allow_unknown_tenants:
            raise ValueError(f"unknown tenant: {key}")
        if self.tenants:
            return self.tenants[0]
        if not self.allow_unknown_tenants:
            raise ValueError("tenant is required")
        return Tenant(tenant_id=key or "tenant_default", tenant_key=key or "tenant_default")

    def user_for(self, user_key_or_id: str | None, *, tenant_id_or_key: str | None = None) -> User:
        value = (user_key_or_id or "").strip()
        tenant_value = (tenant_id_or_key or "").strip()
        tenant = self.tenant_for(tenant_value) if tenant_value else None
        candidates = self.users
        if tenant_value:
            candidates = tuple(
                user for user in candidates if user.tenant_id == tenant_value or user.tenant_key == tenant_value
            )
        for user in candidates:
            if user.user_key == value or user.user_id == value:
                return user
        if not value and candidates:
            return candidates[0]
        if not value and self.users and not tenant_value:
            return self.users[0]
        if not self.allow_unknown_users:
            detail = value or f"tenant {tenant_value}"
            raise ValueError(f"unknown user: {detail}")
        tenant = tenant or self.tenant_for(tenant_value)
        user_id = value.split(":", 1)[1] if value.startswith("pska:") else (value or "user_primary")
        user_key = value if ":" in value else f"pska:{user_id}"
        return User(
            user_id=user_id,
            user_key=user_key,
            tenant_id=tenant.tenant_id,
            tenant_key=tenant.tenant_key,
        )

    def target_for(self, name: str) -> Target:
        target_name = name.strip().lower()
        if target_name in self.targets:
            return self.targets[target_name]
        raise KeyError(f"unknown target: {name}")


def load_config(path: str | os.PathLike[str] | None = None) -> AuthNodeConfig:
    resolved = resolve_config_path(path)
    with resolved.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"config must be a JSON object: {resolved}")
    return AuthNodeConfig.from_dict(data, source_path=resolved)


def resolve_config_path(path: str | os.PathLike[str] | None = None) -> Path:
    explicit = path or os.getenv("AUTHNODE_CONFIG")
    if explicit:
        return Path(explicit).expanduser().resolve()
    cwd = Path.cwd()
    local = cwd / DEFAULT_CONFIG_FILE
    if local.exists():
        return local.resolve()
    example = cwd / EXAMPLE_CONFIG_FILE
    if example.exists():
        return example.resolve()
    return Path(__file__).resolve().parent.parent / EXAMPLE_CONFIG_FILE


def _tenant_from_dict(data: dict[str, Any]) -> Tenant:
    tenant_id = str(data.get("tenant_id") or data.get("id") or data.get("tenant_key") or "").strip()
    tenant_key = str(data.get("tenant_key") or data.get("key") or tenant_id).strip()
    if not tenant_id:
        raise ValueError("tenant_id is required")
    return Tenant(
        tenant_id=tenant_id,
        tenant_key=tenant_key,
        name=str(data.get("name") or tenant_key),
    )


def _user_from_dict(
    data: dict[str, Any],
    tenant_by_id: dict[str, Tenant],
    tenant_by_key: dict[str, Tenant],
) -> User:
    user_id = str(data.get("user_id") or data.get("id") or "").strip()
    user_key = str(data.get("user_key") or "").strip()
    if not user_id and user_key.startswith("pska:"):
        user_id = user_key.split(":", 1)[1]
    if not user_id:
        raise ValueError("user_id is required")
    if not user_key:
        user_key = f"pska:{user_id}"
    tenant_value = str(data.get("tenant_id") or data.get("tenant_key") or "").strip()
    tenant = tenant_by_id.get(tenant_value) or tenant_by_key.get(tenant_value)
    if tenant is None:
        tenant = Tenant(tenant_id=tenant_value or "tenant_default", tenant_key=tenant_value or "tenant_default")
    return User(
        user_id=user_id,
        user_key=user_key,
        tenant_id=str(data.get("tenant_id") or tenant.tenant_id),
        tenant_key=str(data.get("tenant_key") or tenant.tenant_key),
        display_name=str(data.get("display_name") or data.get("name") or user_id),
        email=str(data.get("email") or ""),
        roles=tuple(_string_list(data.get("roles"))),
        groups=tuple(_string_list(data.get("groups"))),
        provider=str(data.get("provider") or "authnode"),
    )


def _target_from_dict(name: str, data: Any) -> Target:
    if isinstance(data, str):
        data = {"base_url": data}
    if not isinstance(data, dict):
        raise ValueError(f"target {name} must be an object or base URL string")
    base_url = str(data.get("base_url") or data.get("url") or "").rstrip("/")
    if not base_url:
        raise ValueError(f"target {name} requires base_url")
    service_token = data.get("service_token")
    return Target(
        name=name,
        base_url=base_url,
        mode=str(data.get("mode") or "jwt").strip().lower(),
        service_token=str(service_token).strip() if service_token else None,
    )


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    return bool(value)
