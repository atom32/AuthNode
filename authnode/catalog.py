from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import secrets
import sqlite3
import time
from typing import Any, Iterable

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from authnode.config import AuthNodeConfig, Tenant, User


SCHEMA_VERSION = 1
SESSION_COOKIE_NAME = "authnode_session"


class CatalogError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CatalogSession:
    session_id: str
    user: User
    tenant: Tenant
    expires_at: int


class AuthCatalog:
    def __init__(self, config: AuthNodeConfig):
        if config.catalog_store.type != "sqlite":
            raise CatalogError(f"unsupported catalog store: {config.catalog_store.type}")
        self.config = config
        self.path = resolve_catalog_path(config)
        self.password_hasher = PasswordHasher()

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, _now()),
            )

    def seed_from_config(self) -> None:
        self.init()
        with self.connect() as conn:
            for tenant in self.config.tenants:
                self.create_tenant(tenant.tenant_id, tenant_key=tenant.tenant_key, name=tenant.name, conn=conn)
            for user in self.config.users:
                password = user.password or self.config.dev_login_password
                self.create_user(
                    user.user_id,
                    display_name=user.display_name,
                    email=user.email,
                    password=password or None,
                    conn=conn,
                )
                self.add_membership(
                    user.user_id,
                    user.tenant_id,
                    roles=user.roles,
                    groups=user.groups,
                    conn=conn,
                )
            conn.commit()

    def create_tenant(self, tenant_id: str, *, tenant_key: str | None = None, name: str = "", conn: sqlite3.Connection | None = None) -> None:
        tenant_id = _required(tenant_id, "tenant_id")
        tenant_key = tenant_key or tenant_id
        own_conn = conn is None
        connection = conn or self.connect()
        try:
            connection.execute(
                """
                INSERT INTO tenants(tenant_id, tenant_key, name, disabled, created_at, updated_at)
                VALUES (?, ?, ?, 0, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                  tenant_key=excluded.tenant_key,
                  name=excluded.name,
                  updated_at=excluded.updated_at
                """,
                (tenant_id, tenant_key, name or tenant_key, _now(), _now()),
            )
            self.audit("tenant.upsert", actor="system", tenant_id=tenant_id, target=tenant_id, conn=connection)
            if own_conn:
                connection.commit()
        finally:
            if own_conn:
                connection.close()

    def list_tenants(self, *, include_disabled: bool = False) -> list[dict[str, Any]]:
        query = "SELECT tenant_id, tenant_key, name, disabled, created_at, updated_at FROM tenants"
        if not include_disabled:
            query += " WHERE disabled = 0"
        query += " ORDER BY tenant_id"
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query)]

    def disable_tenant(self, tenant_id: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE tenants SET disabled = 1, updated_at = ? WHERE tenant_id = ?", (_now(), tenant_id))
            self.audit("tenant.disable", actor="admin-cli", tenant_id=tenant_id, target=tenant_id, conn=conn)

    def create_user(
        self,
        user_id: str,
        *,
        display_name: str = "",
        email: str = "",
        password: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        user_id = _required(user_id, "user_id").removeprefix("pska:")
        user_key = f"pska:{user_id}"
        own_conn = conn is None
        connection = conn or self.connect()
        try:
            connection.execute(
                """
                INSERT INTO users(user_id, user_key, display_name, email, disabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  user_key=excluded.user_key,
                  display_name=excluded.display_name,
                  email=excluded.email,
                  updated_at=excluded.updated_at
                """,
                (user_id, user_key, display_name or user_id, email, _now(), _now()),
            )
            if password is not None:
                self.set_password(user_id, password, conn=connection)
            self.audit("user.upsert", actor="system", target=user_key, conn=connection)
            if own_conn:
                connection.commit()
        finally:
            if own_conn:
                connection.close()

    def list_users(self, *, include_disabled: bool = False) -> list[dict[str, Any]]:
        query = "SELECT user_id, user_key, display_name, email, disabled, created_at, updated_at FROM users"
        if not include_disabled:
            query += " WHERE disabled = 0"
        query += " ORDER BY user_id"
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query)]

    def disable_user(self, user_id: str) -> None:
        user_id = user_id.removeprefix("pska:")
        with self.connect() as conn:
            conn.execute("UPDATE users SET disabled = 1, updated_at = ? WHERE user_id = ?", (_now(), user_id))
            self.audit("user.disable", actor="admin-cli", target=f"pska:{user_id}", conn=conn)

    def set_password(self, user_id: str, password: str, *, conn: sqlite3.Connection | None = None) -> None:
        user_id = user_id.removeprefix("pska:")
        if len(password) < self.config.password_policy.min_length:
            raise CatalogError(f"password must be at least {self.config.password_policy.min_length} characters")
        own_conn = conn is None
        connection = conn or self.connect()
        try:
            password_hash = self.password_hasher.hash(password)
            connection.execute(
                """
                INSERT INTO user_credentials(user_id, password_hash, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  password_hash=excluded.password_hash,
                  updated_at=excluded.updated_at
                """,
                (user_id, password_hash, _now()),
            )
            self.audit("user.password_set", actor="admin-cli", target=f"pska:{user_id}", conn=connection)
            if own_conn:
                connection.commit()
        finally:
            if own_conn:
                connection.close()

    def add_membership(
        self,
        user_id: str,
        tenant_id: str,
        *,
        roles: Iterable[str] = (),
        groups: Iterable[str] = (),
        conn: sqlite3.Connection | None = None,
    ) -> None:
        user_id = user_id.removeprefix("pska:")
        tenant_id = _required(tenant_id, "tenant_id")
        own_conn = conn is None
        connection = conn or self.connect()
        try:
            connection.execute(
                """
                INSERT INTO memberships(user_id, tenant_id, disabled, created_at, updated_at)
                VALUES (?, ?, 0, ?, ?)
                ON CONFLICT(user_id, tenant_id) DO UPDATE SET
                  disabled=0,
                  updated_at=excluded.updated_at
                """,
                (user_id, tenant_id, _now(), _now()),
            )
            self._replace_assignments("membership_roles", user_id, tenant_id, "role", roles, conn=connection)
            self._replace_assignments("membership_groups", user_id, tenant_id, "group_name", groups, conn=connection)
            self.audit("membership.upsert", actor="admin-cli", tenant_id=tenant_id, target=f"pska:{user_id}", conn=connection)
            if own_conn:
                connection.commit()
        finally:
            if own_conn:
                connection.close()

    def remove_membership(self, user_id: str, tenant_id: str) -> None:
        user_id = user_id.removeprefix("pska:")
        with self.connect() as conn:
            conn.execute(
                "UPDATE memberships SET disabled = 1, updated_at = ? WHERE user_id = ? AND tenant_id = ?",
                (_now(), user_id, tenant_id),
            )
            self.audit("membership.disable", actor="admin-cli", tenant_id=tenant_id, target=f"pska:{user_id}", conn=conn)

    def grant_role(self, user_id: str, tenant_id: str, role: str) -> None:
        self._add_assignment("membership_roles", user_id, tenant_id, "role", role, "role.grant")

    def revoke_role(self, user_id: str, tenant_id: str, role: str) -> None:
        self._remove_assignment("membership_roles", user_id, tenant_id, "role", role, "role.revoke")

    def authenticate(self, *, username: str, tenant_id: str, password: str, ip: str = "") -> tuple[User, Tenant]:
        username = _required(username, "username")
        tenant_id = _required(tenant_id, "tenant_id")
        if self.is_rate_limited(username=username, tenant_id=tenant_id, ip=ip):
            self.audit("login.rate_limited", actor=username, tenant_id=tenant_id, target=username, detail={"ip": ip})
            raise CatalogError("too many login attempts")
        with self.connect() as conn:
            row = self._identity_row(conn, username, tenant_id)
            if row is None:
                self.audit("login.failure", actor=username, tenant_id=tenant_id, target=username, detail={"reason": "not_found", "ip": ip}, conn=conn)
                conn.commit()
                raise CatalogError("invalid username or password")
            credential = conn.execute("SELECT password_hash FROM user_credentials WHERE user_id = ?", (row["user_id"],)).fetchone()
            if credential is None:
                self.audit("login.failure", actor=username, tenant_id=tenant_id, target=username, detail={"reason": "no_password", "ip": ip}, conn=conn)
                conn.commit()
                raise CatalogError("invalid username or password")
            try:
                ok = self.password_hasher.verify(str(credential["password_hash"]), password)
            except VerifyMismatchError:
                ok = False
            if not ok:
                self.audit("login.failure", actor=username, tenant_id=tenant_id, target=username, detail={"reason": "bad_password", "ip": ip}, conn=conn)
                conn.commit()
                raise CatalogError("invalid username or password")
            user, tenant = self._user_tenant_from_row(row)
            self.audit("login.success", actor=user.user_key, tenant_id=tenant.tenant_id, target=user.user_key, detail={"ip": ip}, conn=conn)
            conn.commit()
            return user, tenant

    def resolve_identity(self, *, user_key_or_id: str, tenant_id: str) -> tuple[User, Tenant]:
        with self.connect() as conn:
            row = self._identity_row(conn, user_key_or_id, tenant_id)
            if row is None:
                raise CatalogError(f"unknown catalog identity: tenant={tenant_id} user={user_key_or_id}")
            return self._user_tenant_from_row(row)

    def link_provider_account(self, *, provider: str, provider_subject: str, user_id: str, tenant_id: str) -> None:
        user_id = user_id.removeprefix("pska:")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_accounts(provider, provider_subject, user_id, tenant_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, provider_subject) DO UPDATE SET
                  user_id=excluded.user_id,
                  tenant_id=excluded.tenant_id,
                  updated_at=excluded.updated_at
                """,
                (provider, provider_subject, user_id, tenant_id, _now(), _now()),
            )
            self.audit("provider.link", actor="admin-cli", tenant_id=tenant_id, target=f"{provider}:{provider_subject}", conn=conn)

    def resolve_provider_identity(self, *, provider: str, provider_subject: str, fallback_user_id: str, tenant_id: str) -> tuple[User, Tenant]:
        with self.connect() as conn:
            linked = conn.execute(
                """
                SELECT user_id, tenant_id FROM provider_accounts
                WHERE provider = ? AND provider_subject = ?
                """,
                (provider, provider_subject),
            ).fetchone()
            user_id = str(linked["user_id"]) if linked else fallback_user_id
            effective_tenant = str(linked["tenant_id"]) if linked else tenant_id
            row = self._identity_row(conn, user_id, effective_tenant)
            if row is None:
                raise CatalogError(f"provider identity has no active local membership: provider={provider} tenant={effective_tenant}")
            return self._user_tenant_from_row(row)

    def create_session(self, *, user: User, tenant: Tenant, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        now = _now()
        expires_at = now + int(ttl_seconds)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions(session_hash, user_id, tenant_id, created_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (token_hash, user.user_id, tenant.tenant_id, now, expires_at),
            )
            self.audit("session.create", actor=user.user_key, tenant_id=tenant.tenant_id, target=user.user_key, conn=conn)
        return token

    def session_for_token(self, token: str | None) -> CatalogSession | None:
        if not token:
            return None
        token_hash = _token_hash(token)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT s.session_hash, s.expires_at, u.user_id, u.user_key, u.display_name, u.email,
                       t.tenant_id, t.tenant_key, t.name,
                       COALESCE(GROUP_CONCAT(DISTINCT mr.role), '') AS roles,
                       COALESCE(GROUP_CONCAT(DISTINCT mg.group_name), '') AS groups
                FROM sessions s
                JOIN users u ON u.user_id = s.user_id
                JOIN tenants t ON t.tenant_id = s.tenant_id
                JOIN memberships m ON m.user_id = u.user_id AND m.tenant_id = t.tenant_id
                LEFT JOIN membership_roles mr ON mr.user_id = u.user_id AND mr.tenant_id = t.tenant_id
                LEFT JOIN membership_groups mg ON mg.user_id = u.user_id AND mg.tenant_id = t.tenant_id
                WHERE s.session_hash = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                  AND u.disabled = 0
                  AND t.disabled = 0
                  AND m.disabled = 0
                GROUP BY s.session_hash
                """,
                (token_hash, _now()),
            ).fetchone()
            if row is None:
                return None
            user, tenant = self._user_tenant_from_row(row)
            return CatalogSession(session_id=token, user=user, tenant=tenant, expires_at=int(row["expires_at"]))

    def revoke_session(self, token: str | None) -> None:
        if not token:
            return
        with self.connect() as conn:
            conn.execute("UPDATE sessions SET revoked_at = ? WHERE session_hash = ?", (_now(), _token_hash(token)))

    def is_rate_limited(self, *, username: str, tenant_id: str, ip: str = "") -> bool:
        since = _now() - int(self.config.login_rate_limit.window_seconds)
        with self.connect() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*) AS failures FROM audit_events
                WHERE event_type = 'login.failure'
                  AND created_at >= ?
                  AND actor = ?
                  AND tenant_id = ?
                """,
                (since, username, tenant_id),
            ).fetchone()["failures"]
        return int(count) >= int(self.config.login_rate_limit.max_attempts)

    def audit(
        self,
        event_type: str,
        *,
        actor: str = "",
        tenant_id: str = "",
        target: str = "",
        detail: dict[str, Any] | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        own_conn = conn is None
        connection = conn or self.connect()
        try:
            connection.execute(
                """
                INSERT INTO audit_events(event_type, actor, tenant_id, target, detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_type, actor, tenant_id, target, json.dumps(detail or {}, sort_keys=True), _now()),
            )
            if own_conn:
                connection.commit()
        finally:
            if own_conn:
                connection.close()

    def list_audit(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, actor, tenant_id, target, detail_json, created_at
                FROM audit_events
                ORDER BY created_at DESC, audit_id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return [dict(row) for row in rows]

    def _identity_row(self, conn: sqlite3.Connection, user_key_or_id: str, tenant_id: str) -> sqlite3.Row | None:
        value = user_key_or_id.removeprefix("pska:")
        full_key = user_key_or_id if ":" in user_key_or_id else f"pska:{value}"
        return conn.execute(
            """
            SELECT u.user_id, u.user_key, u.display_name, u.email,
                   t.tenant_id, t.tenant_key, t.name,
                   COALESCE(GROUP_CONCAT(DISTINCT mr.role), '') AS roles,
                   COALESCE(GROUP_CONCAT(DISTINCT mg.group_name), '') AS groups
            FROM users u
            JOIN memberships m ON m.user_id = u.user_id
            JOIN tenants t ON t.tenant_id = m.tenant_id
            LEFT JOIN membership_roles mr ON mr.user_id = u.user_id AND mr.tenant_id = t.tenant_id
            LEFT JOIN membership_groups mg ON mg.user_id = u.user_id AND mg.tenant_id = t.tenant_id
            WHERE (u.user_id = ? OR u.user_key = ?)
              AND (t.tenant_id = ? OR t.tenant_key = ?)
              AND u.disabled = 0
              AND t.disabled = 0
              AND m.disabled = 0
            GROUP BY u.user_id, t.tenant_id
            """,
            (value, full_key, tenant_id, tenant_id),
        ).fetchone()

    def _user_tenant_from_row(self, row: sqlite3.Row) -> tuple[User, Tenant]:
        roles = tuple(_split_csv(row["roles"]))
        groups = tuple(_split_csv(row["groups"]))
        tenant = Tenant(tenant_id=str(row["tenant_id"]), tenant_key=str(row["tenant_key"]), name=str(row["name"] or row["tenant_key"]))
        user = User(
            user_id=str(row["user_id"]),
            user_key=str(row["user_key"]),
            tenant_id=tenant.tenant_id,
            tenant_key=tenant.tenant_key,
            display_name=str(row["display_name"] or row["user_id"]),
            email=str(row["email"] or ""),
            roles=roles,
            groups=groups,
            provider="authnode-local-iam",
        )
        return user, tenant

    def _replace_assignments(
        self,
        table: str,
        user_id: str,
        tenant_id: str,
        column: str,
        values: Iterable[str],
        *,
        conn: sqlite3.Connection,
    ) -> None:
        conn.execute(f"DELETE FROM {table} WHERE user_id = ? AND tenant_id = ?", (user_id, tenant_id))
        for value in values:
            cleaned = str(value).strip()
            if cleaned:
                self._ensure_assignment_catalog(table, column, cleaned, conn=conn)
                conn.execute(f"INSERT OR IGNORE INTO {table}(user_id, tenant_id, {column}) VALUES (?, ?, ?)", (user_id, tenant_id, cleaned))

    def _add_assignment(self, table: str, user_id: str, tenant_id: str, column: str, value: str, event_type: str) -> None:
        user_id = user_id.removeprefix("pska:")
        with self.connect() as conn:
            self._ensure_assignment_catalog(table, column, value, conn=conn)
            conn.execute(f"INSERT OR IGNORE INTO {table}(user_id, tenant_id, {column}) VALUES (?, ?, ?)", (user_id, tenant_id, value))
            self.audit(event_type, actor="admin-cli", tenant_id=tenant_id, target=f"pska:{user_id}", detail={column: value}, conn=conn)

    def _remove_assignment(self, table: str, user_id: str, tenant_id: str, column: str, value: str, event_type: str) -> None:
        user_id = user_id.removeprefix("pska:")
        with self.connect() as conn:
            conn.execute(f"DELETE FROM {table} WHERE user_id = ? AND tenant_id = ? AND {column} = ?", (user_id, tenant_id, value))
            self.audit(event_type, actor="admin-cli", tenant_id=tenant_id, target=f"pska:{user_id}", detail={column: value}, conn=conn)

    def _ensure_assignment_catalog(self, table: str, column: str, value: str, *, conn: sqlite3.Connection) -> None:
        if table == "membership_roles" and column == "role":
            conn.execute("INSERT OR IGNORE INTO roles(role) VALUES (?)", (value,))
        if table == "membership_groups" and column == "group_name":
            conn.execute("INSERT OR IGNORE INTO groups(group_name) VALUES (?)", (value,))


def resolve_catalog_path(config: AuthNodeConfig) -> Path:
    raw = Path(config.catalog_store.path).expanduser()
    if raw.is_absolute():
        return raw
    base = config.source_path.parent if config.source_path else Path.cwd()
    return (base / raw).resolve()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _required(value: str, name: str) -> str:
    text = (value or "").strip()
    if not text:
        raise CatalogError(f"{name} is required")
    return text


def _now() -> int:
    return int(time.time())


def _split_csv(value: Any) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY,
  tenant_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  user_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS roles (
  role TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS groups (
  group_name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS membership_roles (
  user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (user_id, tenant_id, role),
  FOREIGN KEY (user_id, tenant_id) REFERENCES memberships(user_id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS membership_groups (
  user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  group_name TEXT NOT NULL,
  PRIMARY KEY (user_id, tenant_id, group_name),
  FOREIGN KEY (user_id, tenant_id) REFERENCES memberships(user_id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  session_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS provider_accounts (
  provider TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS audit_events (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_login_failures ON audit_events(event_type, created_at, actor, tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, tenant_id, expires_at);
"""
