from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import html
import json
import secrets
import string
from threading import Lock
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from authnode.config import AuthNodeConfig, Target, Tenant, User
from authnode.identity import (
    issue_identity_token_for_user,
    issue_identity_token,
    outbound_headers_for_target,
    public_tenant,
    public_user,
    token_response,
    trusted_headers_for_user,
)
from authnode.oidc import (
    OidcCache,
    OidcError,
    authorization_url,
    code_challenge,
    exchange_code_for_identity,
    logout_url,
)


class AuthNodeHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], config: AuthNodeConfig):
        super().__init__(server_address, RequestHandlerClass)
        self.config = config
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.auth_codes_lock = Lock()
        self.oidc_states: dict[str, dict[str, Any]] = {}
        self.oidc_states_lock = Lock()
        self.oidc_cache = OidcCache()

    def issue_auth_code(
        self,
        *,
        user_key: str | None,
        tenant: str | None,
        target: str,
        return_to: str,
        state: str | None,
        next_path: str | None,
        identity: Mapping[str, Any] | None = None,
    ) -> str:
        code = secrets.token_urlsafe(32)
        with self.auth_codes_lock:
            self.auth_codes[code] = {
                "user_key": user_key,
                "tenant": tenant,
                "target": target,
                "return_to": return_to,
                "state": state or "",
                "next": next_path or "",
                "exp": time.time() + 300,
            }
            if identity:
                self.auth_codes[code]["identity"] = dict(identity)
        return code

    def consume_auth_code(self, code: str) -> dict[str, Any] | None:
        with self.auth_codes_lock:
            payload = self.auth_codes.pop(code, None)
        if not payload:
            return None
        if time.time() >= float(payload.get("exp") or 0):
            return None
        return payload

    def issue_oidc_state(
        self,
        *,
        target: str,
        return_to: str,
        next_path: str | None,
        state: str | None,
    ) -> dict[str, str]:
        oidc_state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = _pkce_verifier()
        with self.oidc_states_lock:
            self.oidc_states[oidc_state] = {
                "target": target,
                "return_to": return_to,
                "next": next_path or "",
                "state": state or "",
                "nonce": nonce,
                "code_verifier": code_verifier,
                "exp": time.time() + 600,
            }
        return {
            "state": oidc_state,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge(code_verifier),
        }

    def consume_oidc_state(self, state: str) -> dict[str, Any] | None:
        with self.oidc_states_lock:
            payload = self.oidc_states.pop(state, None)
        if not payload:
            return None
        if time.time() >= float(payload.get("exp") or 0):
            return None
        return payload


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
            if parsed.path == "/login" and self.command == "GET":
                self._handle_login_form(parsed.query)
                return
            if parsed.path == "/login" and self.command == "POST":
                self._handle_login_submit()
                return
            if parsed.path == "/oidc/callback" and self.command == "GET":
                self._handle_oidc_callback(parsed.query)
                return
            if parsed.path == "/logout" and self.command == "GET":
                self._handle_logout(parsed.query)
                return
            if parsed.path == "/v1/auth/exchange":
                self._handle_auth_exchange()
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

    def _handle_login_form(self, query: str) -> None:
        params = parse_qs(query)
        target = _first(params.get("target")) or "pska"
        return_to = _first(params.get("return_to")) or ""
        if not return_to:
            self._error(HTTPStatus.BAD_REQUEST, "return_to is required")
            return
        next_path = _first(params.get("next")) or "/"
        if self.server.config.browser_login_provider == "keycloak" and not _truthy(_first(params.get("local"))):
            oidc = self.server.issue_oidc_state(
                target=target,
                return_to=return_to,
                next_path=next_path,
                state=_first(params.get("state")),
            )
            try:
                login_url = authorization_url(
                    self.server.config,
                    self.server.oidc_cache,
                    state=oidc["state"],
                    nonce=oidc["nonce"],
                    code_challenge=oidc["code_challenge"],
                )
            except OidcError as exc:
                self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
                return
            self._redirect(login_url)
            return
        requested_user = _first(params.get("user_key"), params.get("user_id"))
        requested_tenant = _first(params.get("tenant_id"), params.get("tenant_key"))
        default_user = self.server.config.user_for(requested_user, tenant_id_or_key=requested_tenant)
        username = requested_user or default_user.user_id
        if username.startswith("pska:"):
            username = username.split(":", 1)[1]
        tenant_value = requested_tenant or default_user.tenant_key or default_user.tenant_id
        tenant_options = "\n".join(
            f'<option value="{html.escape(tenant.tenant_key or tenant.tenant_id, quote=True)}">{html.escape(tenant.name or tenant.tenant_key or tenant.tenant_id)}</option>'
            for tenant in self.server.config.tenants
        )
        body = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AuthNode Login</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f7f7f4; color: #171717; }}
    main {{ width: min(430px, calc(100vw - 32px)); border: 1px solid #d7d7cf; border-radius: 8px; background: #fff; padding: 28px; box-shadow: 0 18px 50px rgba(28, 31, 35, 0.10); }}
    h1 {{ margin: 0 0 8px; font-size: 24px; letter-spacing: 0; }}
    p {{ margin: 0 0 20px; color: #666; line-height: 1.5; }}
    label {{ display: grid; gap: 8px; margin: 16px 0; font-size: 13px; color: #555; }}
    select, input {{ min-height: 42px; border: 1px solid #cbc7ba; border-radius: 7px; padding: 0 12px; font: inherit; background: #fff; }}
    small {{ color: #777; line-height: 1.4; }}
    button {{ width: 100%; height: 42px; margin-top: 8px; border: 0; border-radius: 7px; background: #245b52; color: white; font-weight: 700; cursor: pointer; }}
  </style>
</head>
<body>
  <main>
    <h1>AuthNode</h1>
    <p>登录后继续访问 {html.escape(target)}。这是本地开发登录入口，不向浏览器暴露服务 token。</p>
    <form method="post" action="/login">
      <input type="hidden" name="target" value="{html.escape(target, quote=True)}">
      <input type="hidden" name="return_to" value="{html.escape(return_to, quote=True)}">
      <input type="hidden" name="next" value="{html.escape(next_path, quote=True)}">
      <input type="hidden" name="state" value="{html.escape(_first(params.get("state")) or "", quote=True)}">
      <label>Tenant
        <input name="tenant_id" list="tenant-options" value="{html.escape(tenant_value, quote=True)}" autocomplete="organization" required>
        <datalist id="tenant-options">
          {tenant_options}
        </datalist>
      </label>
      <label>Username
        <input name="username" value="{html.escape(username, quote=True)}" autocomplete="username" required>
      </label>
      <label>Password
        <input name="password" type="password" autocomplete="current-password" required>
      </label>
      <button type="submit">登录</button>
    </form>
  </main>
</body>
</html>"""
        self._html(body)

    def _handle_login_submit(self) -> None:
        form = self._form_body()
        identity = _first(form.get("identity"))
        username = _first(form.get("username"), form.get("user_key"), form.get("user_id"))
        tenant = _first(form.get("tenant_id"), form.get("tenant_key"))
        password = _first(form.get("password")) or ""
        target = _first(form.get("target")) or "pska"
        return_to = _first(form.get("return_to"))
        if not return_to:
            self._error(HTTPStatus.BAD_REQUEST, "return_to is required")
            return
        if identity:
            user_key, tenant = _split_identity(identity)
        else:
            if not username:
                self._error(HTTPStatus.BAD_REQUEST, "username is required")
                return
            user_key = username if ":" in username else f"pska:{username}"
        user = self.server.config.user_for(user_key, tenant_id_or_key=tenant)
        if not _verify_login_password(self.server.config, user, password):
            self._error(HTTPStatus.UNAUTHORIZED, "invalid username or password")
            return
        tenant_item = self.server.config.tenant_for(tenant or user.tenant_id or user.tenant_key)
        code = self.server.issue_auth_code(
            user_key=user.user_key,
            tenant=tenant_item.tenant_id,
            target=target,
            return_to=return_to,
            state=_first(form.get("state")),
            next_path=_first(form.get("next")),
        )
        params = {"code": code}
        state = _first(form.get("state"))
        next_path = _first(form.get("next"))
        if state:
            params["state"] = state
        if next_path:
            params["next"] = next_path
        self._redirect(_append_query(return_to, params))

    def _handle_oidc_callback(self, query: str) -> None:
        params = parse_qs(query)
        error = _first(params.get("error"))
        if error:
            detail = _first(params.get("error_description")) or error
            self._error(HTTPStatus.UNAUTHORIZED, f"Keycloak login failed: {detail}")
            return
        state = _first(params.get("state")) or ""
        code = _first(params.get("code")) or ""
        if not state or not code:
            self._error(HTTPStatus.BAD_REQUEST, "OIDC callback requires state and code")
            return
        state_payload = self.server.consume_oidc_state(state)
        if state_payload is None:
            self._error(HTTPStatus.UNAUTHORIZED, "OIDC state is invalid or expired")
            return
        try:
            identity = exchange_code_for_identity(
                self.server.config,
                self.server.oidc_cache,
                code=code,
                code_verifier=str(state_payload.get("code_verifier") or ""),
                nonce=str(state_payload.get("nonce") or ""),
            )
        except OidcError as exc:
            self._error(HTTPStatus.UNAUTHORIZED, str(exc))
            return
        auth_code = self.server.issue_auth_code(
            user_key=identity.user.user_key,
            tenant=identity.tenant.tenant_id,
            target=str(state_payload.get("target") or "pska"),
            return_to=str(state_payload.get("return_to") or ""),
            state=str(state_payload.get("state") or ""),
            next_path=str(state_payload.get("next") or ""),
            identity=_identity_payload(identity.user, identity.tenant),
        )
        redirect_params = {"code": auth_code}
        app_state = str(state_payload.get("state") or "")
        next_path = str(state_payload.get("next") or "")
        if app_state:
            redirect_params["state"] = app_state
        if next_path:
            redirect_params["next"] = next_path
        self._redirect(_append_query(str(state_payload.get("return_to") or ""), redirect_params))

    def _handle_logout(self, query: str) -> None:
        params = parse_qs(query)
        return_to = _first(params.get("return_to")) or "/"
        if self.server.config.browser_login_provider == "keycloak":
            try:
                self._redirect(logout_url(self.server.config, self.server.oidc_cache, return_to=return_to))
                return
            except OidcError:
                pass
        self._redirect(return_to)

    def _handle_auth_exchange(self) -> None:
        body = self._json_body()
        code = str(body.get("code") or "").strip()
        if not code:
            self._error(HTTPStatus.BAD_REQUEST, "code is required")
            return
        payload = self.server.consume_auth_code(code)
        if payload is None:
            self._error(HTTPStatus.BAD_REQUEST, "auth code is invalid or expired")
            return
        target_name = str(body.get("target") or payload.get("target") or "pska").strip().lower()
        if target_name != str(payload.get("target") or "").strip().lower():
            self._error(HTTPStatus.BAD_REQUEST, "auth code target mismatch")
            return
        identity = payload.get("identity")
        if isinstance(identity, dict):
            user, tenant = _identity_from_payload(identity)
            token, claims = issue_identity_token_for_user(
                self.server.config,
                user,
                tenant=tenant,
                audience=_target_audience(target_name),
            )
        else:
            token, claims = issue_identity_token(
                self.server.config,
                str(payload.get("user_key") or ""),
                tenant_id_or_key=str(payload.get("tenant") or ""),
                audience=_target_audience(target_name),
            )
        response = token_response(token, claims)
        response.update(
            {
                "state": payload.get("state") or "",
                "next": payload.get("next") or "",
                "target": target_name,
            }
        )
        self._json(response)

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

    def _form_body(self) -> dict[str, list[str]]:
        length = int(self.headers.get("content-length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return parse_qs(raw.decode("utf-8"), keep_blank_values=True)

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
            "browser_login_provider": config.browser_login_provider,
            "keycloak_configured": bool(config.keycloak.issuer_url and config.keycloak.client_id),
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

    def _html(self, payload: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, status: HTTPStatus = HTTPStatus.FOUND) -> None:
        self.send_response(status)
        self.send_header("location", location)
        self.send_header("content-length", "0")
        self.end_headers()

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


def _target_audience(name: str) -> list[str]:
    target = name.strip().lower()
    if target in {"fastreact", "pska"}:
        return [target]
    return [target]


def _append_query(url: str, params: Mapping[str, str]) -> str:
    split = urlsplit(url)
    existing = parse_qs(split.query, keep_blank_values=True)
    for key, value in params.items():
        existing[key] = [value]
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(existing, doseq=True), split.fragment))


def _split_identity(value: str) -> tuple[str, str | None]:
    user_key, _, tenant = value.partition("|")
    return user_key.strip(), tenant.strip() or None


def _verify_login_password(config: AuthNodeConfig, user: Any, password: str) -> bool:
    expected = str(getattr(user, "password", "") or config.dev_login_password or "")
    if not expected:
        return False
    return hmac.compare_digest(password, expected)


def _identity_payload(user: User, tenant: Tenant) -> dict[str, Any]:
    return {
        "user_id": user.user_id,
        "user_key": user.user_key,
        "tenant_id": tenant.tenant_id,
        "tenant_key": tenant.tenant_key,
        "display_name": user.display_name,
        "email": user.email,
        "roles": list(user.roles),
        "groups": list(user.groups),
        "provider": user.provider,
    }


def _identity_from_payload(payload: Mapping[str, Any]) -> tuple[User, Tenant]:
    tenant = Tenant(
        tenant_id=str(payload.get("tenant_id") or payload.get("tenant_key") or ""),
        tenant_key=str(payload.get("tenant_key") or payload.get("tenant_id") or ""),
    )
    user_id = str(payload.get("user_id") or "").removeprefix("pska:")
    user_key = str(payload.get("user_key") or user_id)
    if user_key and ":" not in user_key:
        user_key = f"pska:{user_key}"
    user = User(
        user_id=user_id,
        user_key=user_key,
        tenant_id=tenant.tenant_id,
        tenant_key=tenant.tenant_key,
        display_name=str(payload.get("display_name") or user_id),
        email=str(payload.get("email") or ""),
        roles=tuple(_list_value(payload.get("roles"))),
        groups=tuple(_list_value(payload.get("groups"))),
        provider=str(payload.get("provider") or "keycloak"),
    )
    return user, tenant


def _pkce_verifier() -> str:
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(64))


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _list_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _user_option(user: Mapping[str, Any], *, selected_user: str | None, selected_tenant: str | None) -> str:
    user_key = str(user.get("user_key") or user.get("user_id") or "")
    tenant_id = str(user.get("tenant_id") or user.get("tenant_key") or "")
    label_parts = [
        str(user.get("display_name") or user.get("user_id") or user_key),
        f"{user_key}",
        f"tenant={tenant_id}",
    ]
    selected = ""
    if selected_user and selected_tenant:
        user_matches = selected_user in {user_key, str(user.get("user_id") or "")}
        tenant_matches = selected_tenant in {tenant_id, str(user.get("tenant_key") or "")}
        selected = " selected" if user_matches and tenant_matches else ""
    value = html.escape(f"{user_key}|{tenant_id}", quote=True)
    label = html.escape(" / ".join(part for part in label_parts if part), quote=True)
    return f'<option value="{value}"{selected}>{label}</option>'


def _bearer_token(value: str | None) -> str | None:
    if not value:
        return None
    prefix = "Bearer "
    return value[len(prefix) :].strip() if value.startswith(prefix) else None
