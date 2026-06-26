from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from authnode.config import AuthNodeConfig, Target
from authnode.identity import (
    issue_identity_token,
    outbound_headers_for_target,
    public_tenant,
    public_user,
    token_response,
    trusted_headers_for_user,
)


class AuthNodeHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], config: AuthNodeConfig):
        super().__init__(server_address, RequestHandlerClass)
        self.config = config


class AuthNodeHandler(BaseHTTPRequestHandler):
    server: AuthNodeHTTPServer

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _dispatch(self) -> None:
        parsed = urlsplit(self.path)
        try:
            if parsed.path == "/health":
                self._json({"ok": True})
                return
            if parsed.path == "/ready":
                self._json(self._ready_payload())
                return
            if parsed.path == "/v1/tenants":
                self._json({"tenants": [public_tenant(item) for item in self.server.config.tenants]})
                return
            if parsed.path == "/v1/users":
                self._json({"users": [public_user(item) for item in self.server.config.users]})
                return
            if parsed.path == "/v1/token":
                if not self._require_admin_auth():
                    return
                self._handle_token(parsed.query)
                return
            if parsed.path == "/v1/headers":
                if not self._require_admin_auth():
                    return
                self._handle_headers(parsed.query)
                return
            if parsed.path.startswith("/proxy/"):
                self._handle_proxy(parsed)
                return
            self._error(HTTPStatus.NOT_FOUND, "not found")
        except KeyError as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_token(self, query: str) -> None:
        params = parse_qs(query)
        body = self._json_body() if self.command == "POST" else {}
        user_key = _first(body.get("user_key"), params.get("user_key"), body.get("user_id"), params.get("user_id"))
        tenant = _first(body.get("tenant_id"), params.get("tenant_id"), body.get("tenant_key"), params.get("tenant_key"))
        audience = body.get("audience") or _first(params.get("audience"))
        ttl = body.get("ttl_seconds") or _first(params.get("ttl_seconds"))
        token, claims = issue_identity_token(
            self.server.config,
            user_key,
            tenant_id_or_key=tenant,
            audience=audience,
            ttl_seconds=int(ttl) if ttl else None,
        )
        self._json(token_response(token, claims))

    def _handle_headers(self, query: str) -> None:
        params = parse_qs(query)
        user_key = _first(params.get("user_key"), params.get("user_id"))
        tenant = _first(params.get("tenant_id"), params.get("tenant_key"))
        target = _first(params.get("target")) or "both"
        mode = (_first(params.get("mode")) or "trusted_headers").strip().lower()
        if mode == "jwt":
            token, claims = issue_identity_token(
                self.server.config,
                user_key,
                tenant_id_or_key=tenant,
                audience=None if target == "both" else target,
            )
            self._json({"headers": {"Authorization": f"Bearer {token}"}, "claims": claims})
            return
        headers = trusted_headers_for_user(self.server.config, user_key, tenant_id_or_key=tenant, target=target)
        self._json({"headers": headers})

    def _handle_proxy(self, parsed: Any) -> None:
        rest = parsed.path[len("/proxy/") :]
        target_name, _, target_path = rest.partition("/")
        if not target_name:
            self._error(HTTPStatus.BAD_REQUEST, "proxy target is required")
            return
        target = self.server.config.target_for(target_name)
        params = parse_qs(parsed.query)
        user_key = (
            self.headers.get("X-AuthNode-User-Key")
            or _first(params.get("authnode_user_key"))
            or _first(params.get("user_key"))
        )
        tenant = (
            self.headers.get("X-AuthNode-Tenant-Id")
            or _first(params.get("authnode_tenant_id"))
            or _first(params.get("tenant_id"))
        )
        mode = self.headers.get("X-AuthNode-Mode") or _first(params.get("authnode_mode"))
        clean_query = _clean_proxy_query(parsed.query)
        upstream_url = _join_target_url(target, target_path, clean_query)
        body = self.rfile.read(int(self.headers.get("content-length") or 0)) or None
        headers = self._proxy_headers(target, user_key=user_key, tenant=tenant, mode=mode)
        request = Request(upstream_url, data=body, headers=headers, method=self.command)
        try:
            with urlopen(request, timeout=30) as response:
                self._proxy_response(response.status, dict(response.headers), response.read())
        except HTTPError as exc:
            self._proxy_response(exc.code, dict(exc.headers), exc.read())
        except URLError as exc:
            self._error(HTTPStatus.BAD_GATEWAY, f"upstream unavailable: {exc.reason}")

    def _proxy_headers(self, target: Target, *, user_key: str | None, tenant: str | None, mode: str | None) -> dict[str, str]:
        injected_headers = outbound_headers_for_target(
            self.server.config,
            target,
            user_key,
            tenant_id_or_key=tenant,
            mode=mode,
        )
        return proxy_forward_headers(self.headers, injected_headers)

    def _json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _ready_payload(self) -> dict[str, Any]:
        config = self.server.config
        return {
            "ok": True,
            "issuer": config.issuer,
            "config": str(config.source_path) if config.source_path else None,
            "strict_identity": config.strict_identity,
            "allow_unknown_users": config.allow_unknown_users,
            "allow_unknown_tenants": config.allow_unknown_tenants,
            "admin_token_configured": bool(config.admin_token),
            "tenants": len(config.tenants),
            "users": len(config.users),
            "targets": {
                name: {"base_url": target.base_url, "mode": target.mode}
                for name, target in config.targets.items()
            },
        }

    def _require_admin_auth(self) -> bool:
        expected = self.server.config.admin_token
        if not expected:
            if self.server.config.strict_identity:
                self._error(HTTPStatus.SERVICE_UNAVAILABLE, "admin_token is required when strict_identity is enabled")
                return False
            return True
        provided = self.headers.get("X-AuthNode-Admin-Token") or _bearer_token(self.headers.get("Authorization"))
        if provided and hmac.compare_digest(provided, expected):
            return True
        self._error(HTTPStatus.UNAUTHORIZED, "AuthNode admin token required")
        return False

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json({"ok": False, "error": message}, status=status)

    def _proxy_response(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() in HOP_HEADERS or key.lower() == "content-length":
                continue
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def serve(config: AuthNodeConfig, *, host: str | None = None, port: int | None = None) -> None:
    address = (host or config.host, int(port or config.port))
    server = AuthNodeHTTPServer(address, AuthNodeHandler, config)
    print(f"AuthNode listening on http://{address[0]}:{address[1]}")
    print(f"Config: {config.source_path or '<memory>'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAuthNode stopped.")
    finally:
        server.server_close()


def proxy_forward_headers(inbound_headers: Mapping[str, str], injected_headers: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in inbound_headers.items():
        lower = key.lower()
        if lower in HOP_HEADERS or lower.startswith("x-fastreact-") or lower.startswith("x-pska-"):
            continue
        if lower in {"authorization", "host", "content-length"}:
            continue
        if lower.startswith("x-authnode-"):
            continue
        result[key] = value
    result.update(dict(injected_headers))
    return result


def _first(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, list):
            if value and str(value[0]).strip():
                return str(value[0]).strip()
            continue
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _clean_proxy_query(query: str) -> str:
    params = parse_qs(query, keep_blank_values=True)
    for key in list(params):
        if key.startswith("authnode_") or key in {"user_key", "tenant_id"}:
            params.pop(key, None)
    return urlencode(params, doseq=True)


def _join_target_url(target: Target, target_path: str, query: str) -> str:
    path = "/" + target_path.lstrip("/")
    split = urlsplit(target.base_url)
    base_path = split.path.rstrip("/")
    return urlunsplit((split.scheme, split.netloc, f"{base_path}{path}", query, ""))


def _bearer_token(value: str | None) -> str | None:
    if not value:
        return None
    prefix = "Bearer "
    return value[len(prefix) :].strip() if value.startswith(prefix) else None
