from __future__ import annotations

import json
import time
import unittest
from threading import Thread
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from authnode.config import AuthNodeConfig
from authnode.contract import check_contract
from authnode.identity import issue_identity_token, trusted_headers_for_user
from authnode.jwt import decode_hs256
from authnode.server import AuthNodeHTTPServer, AuthNodeHandler, proxy_forward_headers


CONFIG_DATA = {
    "jwt_secret": "test-secret",
    "issuer": "authnode.test",
    "dev_login_password": "pska-local",
    "tenants": [{"tenant_id": "tenant_a", "tenant_key": "tenant_a"}],
    "users": [
        {
            "user_id": "alice",
            "user_key": "pska:alice",
            "tenant_id": "tenant_a",
            "tenant_key": "tenant_a",
            "display_name": "Alice",
            "password": "alice-local",
            "email": "alice@example.test",
            "roles": ["admin", "writer"],
            "groups": ["local"],
        }
    ],
    "targets": {
        "fastreact": {"base_url": "http://127.0.0.1:8000", "mode": "jwt"},
        "pska": {"base_url": "http://127.0.0.1:8765", "mode": "jwt"},
    },
}


class AuthNodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AuthNodeConfig.from_dict(CONFIG_DATA)

    def test_token_claims_match_fastreact_and_pska_contract(self) -> None:
        token, claims = issue_identity_token(self.config, "pska:alice", audience=["fastreact", "pska"])

        decoded = decode_hs256(token, "test-secret", issuer="authnode.test", audience="fastreact")

        self.assertEqual(decoded["sub"], "pska:alice")
        self.assertEqual(decoded["tenant_id"], "tenant_a")
        self.assertEqual(decoded["tenant_key"], "tenant_a")
        self.assertEqual(decoded["user_id"], "alice")
        self.assertEqual(decoded["roles"], ["admin", "writer"])
        self.assertEqual(claims["aud"], ["fastreact", "pska"])

    def test_trusted_headers_emit_target_specific_aliases(self) -> None:
        headers = trusted_headers_for_user(self.config, "pska:alice", target="both")

        self.assertEqual(headers["X-FastReAct-User-Key"], "pska:alice")
        self.assertEqual(headers["X-FastReAct-Tenant-Key"], "tenant_a")
        self.assertEqual(headers["X-PSKA-User-Id"], "alice")
        self.assertEqual(headers["X-PSKA-Tenant-Id"], "tenant_a")
        self.assertEqual(headers["X-PSKA-Roles"], "admin,writer")

    def test_unknown_user_defaults_to_pska_user_key(self) -> None:
        token, claims = issue_identity_token(self.config, "bob", tenant_id_or_key="tenant_a", audience="pska")
        decoded = decode_hs256(token, "test-secret", issuer="authnode.test", audience="pska")

        self.assertEqual(claims["sub"], "pska:bob")
        self.assertEqual(decoded["user_id"], "bob")

    def test_default_audience_contains_both_services(self) -> None:
        token, claims = issue_identity_token(self.config, "pska:alice")

        decode_hs256(token, "test-secret", issuer="authnode.test", audience="fastreact")
        decode_hs256(token, "test-secret", issuer="authnode.test", audience="pska")
        self.assertEqual(claims["aud"], ["fastreact", "pska"])

    def test_strict_identity_rejects_unknown_user(self) -> None:
        config = AuthNodeConfig.from_dict(
            {
                **CONFIG_DATA,
                "strict_identity": True,
                "allow_unknown_users": False,
                "allow_unknown_tenants": False,
                "admin_token": "admin-secret",
            }
        )

        with self.assertRaisesRegex(ValueError, "unknown user"):
            issue_identity_token(config, "bob", tenant_id_or_key="tenant_a")

    def test_strict_identity_rejects_unknown_tenant(self) -> None:
        config = AuthNodeConfig.from_dict(
            {
                **CONFIG_DATA,
                "strict_identity": True,
                "allow_unknown_users": False,
                "allow_unknown_tenants": False,
                "admin_token": "admin-secret",
            }
        )

        with self.assertRaisesRegex(ValueError, "unknown tenant"):
            issue_identity_token(config, "pska:alice", tenant_id_or_key="missing")

    def test_token_endpoint_requires_admin_token_when_configured(self) -> None:
        config = AuthNodeConfig.from_dict({**CONFIG_DATA, "admin_token": "admin-secret"})
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with self.assertRaises(HTTPError) as blocked:
                urlopen(f"{base_url}/v1/token?user_key=pska:alice", timeout=5)
            self.assertEqual(blocked.exception.code, 401)

            request = Request(
                f"{base_url}/v1/token?user_key=pska:alice",
                headers={"X-AuthNode-Admin-Token": "admin-secret"},
            )
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_browser_login_issues_one_time_code_for_exchange(self) -> None:
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, self.config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            with urlopen(f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback", timeout=5) as response:
                page = response.read().decode("utf-8")
            self.assertIn("Username", page)
            self.assertIn("Password", page)
            self.assertIn("tenant_a", page)

            body = urlencode(
                {
                    "username": "alice",
                    "tenant_id": "tenant_a",
                    "password": "alice-local",
                    "target": "pska",
                    "return_to": "http://pska.local/auth/callback",
                    "next": "/",
                }
            ).encode()
            request = Request(
                f"{base_url}/login",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            response = _open_no_redirect(opener, request)
            self.assertEqual(response.code, 302)
            location = response.headers["Location"]
            params = parse_qs(urlsplit(location).query)
            code = params["code"][0]

            exchange_body = json.dumps({"code": code, "target": "pska"}).encode()
            exchange_request = Request(
                f"{base_url}/v1/auth/exchange",
                data=exchange_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(exchange_request, timeout=5) as exchange_response:
                exchanged = json.loads(exchange_response.read().decode("utf-8"))
            decoded = decode_hs256(exchanged["access_token"], "test-secret", issuer="authnode.test", audience="pska")
            self.assertEqual(decoded["sub"], "pska:alice")
            self.assertEqual(decoded["tenant_id"], "tenant_a")
            self.assertEqual(exchanged["target"], "pska")

            with self.assertRaises(HTTPError) as blocked:
                urlopen(exchange_request, timeout=5)
            self.assertEqual(blocked.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_browser_login_rejects_bad_password(self) -> None:
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, self.config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            body = urlencode(
                {
                    "username": "alice",
                    "tenant_id": "tenant_a",
                    "password": "wrong",
                    "target": "pska",
                    "return_to": "http://pska.local/auth/callback",
                }
            ).encode()
            request = Request(
                f"{base_url}/login",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as blocked:
                urlopen(request, timeout=5)
            self.assertEqual(blocked.exception.code, 401)

            legacy_body = urlencode(
                {
                    "identity": "pska:alice|tenant_a",
                    "target": "pska",
                    "return_to": "http://pska.local/auth/callback",
                }
            ).encode()
            legacy_request = Request(
                f"{base_url}/login",
                data=legacy_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as legacy_blocked:
                urlopen(legacy_request, timeout=5)
            self.assertEqual(legacy_blocked.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_browser_login_preserves_unknown_tenant_when_catalog_exists(self) -> None:
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, self.config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            body = urlencode(
                {
                    "username": "e2e-writer",
                    "tenant_id": "tenant_dynamic",
                    "password": "pska-local",
                    "target": "pska",
                    "return_to": "http://pska.local/auth/callback",
                    "next": "/",
                }
            ).encode()
            request = Request(
                f"{base_url}/login",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            response = _open_no_redirect(opener, request)
            location = response.headers["Location"]
            code = parse_qs(urlsplit(location).query)["code"][0]

            exchange_body = json.dumps({"code": code, "target": "pska"}).encode()
            exchange_request = Request(
                f"{base_url}/v1/auth/exchange",
                data=exchange_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(exchange_request, timeout=5) as exchange_response:
                exchanged = json.loads(exchange_response.read().decode("utf-8"))
            decoded = decode_hs256(exchanged["access_token"], "test-secret", issuer="authnode.test", audience="pska")
            self.assertEqual(decoded["sub"], "pska:e2e-writer")
            self.assertEqual(decoded["tenant_id"], "tenant_dynamic")
            self.assertEqual(decoded["tenant_key"], "tenant_dynamic")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_keycloak_login_redirects_to_oidc_authorization_endpoint(self) -> None:
        config = keycloak_config()
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        provider = MockOidcProvider(config)
        try:
            with patch("authnode.oidc.urlopen", provider):
                response = _open_no_redirect(
                    opener,
                    f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback&next=%2F",
                )
            self.assertEqual(response.code, 302)
            location = response.headers["Location"]
            split = urlsplit(location)
            params = parse_qs(split.query)
            self.assertEqual(f"{split.scheme}://{split.netloc}{split.path}", "http://keycloak.test/auth")
            self.assertEqual(params["client_id"], ["authnode"])
            self.assertEqual(params["redirect_uri"], ["http://authnode.test/oidc/callback"])
            self.assertEqual(params["code_challenge_method"], ["S256"])
            self.assertIn(params["state"][0], server.oidc_states)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_keycloak_callback_exchanges_verified_claims_for_authnode_code(self) -> None:
        config = keycloak_config()
        key, jwk = rsa_key("kid-current")
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            with patch("authnode.oidc.urlopen", MockOidcProvider(config)):
                login = _open_no_redirect(
                    opener,
                    f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback&next=%2Fwriter",
                )
            state = parse_qs(urlsplit(login.headers["Location"]).query)["state"][0]
            nonce = server.oidc_states[state]["nonce"]
            token = oidc_token(config, key, "kid-current", nonce=nonce)
            provider = MockOidcProvider(config, id_token=token, jwks_sequence=[{"keys": [jwk]}])

            with patch("authnode.oidc.urlopen", provider):
                callback = _open_no_redirect(opener, f"{base_url}/oidc/callback?state={state}&code=mock-code")
            self.assertEqual(callback.code, 302)
            location = callback.headers["Location"]
            callback_params = parse_qs(urlsplit(location).query)
            self.assertEqual(urlsplit(location).path, "/auth/callback")
            self.assertEqual(callback_params["next"], ["/writer"])
            code = callback_params["code"][0]

            exchange_body = json.dumps({"code": code, "target": "pska"}).encode()
            exchange_request = Request(
                f"{base_url}/v1/auth/exchange",
                data=exchange_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(exchange_request, timeout=5) as exchange_response:
                exchanged = json.loads(exchange_response.read().decode("utf-8"))
            decoded = decode_hs256(exchanged["access_token"], "test-secret", issuer="authnode.test", audience="pska")
            self.assertEqual(decoded["sub"], "pska:keycloak-writer")
            self.assertEqual(decoded["tenant_id"], "tenant_oidc")
            self.assertEqual(decoded["user_id"], "keycloak-writer")
            self.assertEqual(decoded["provider"], "keycloak")
            self.assertEqual(decoded["roles"], ["writer", "admin"])
            self.assertEqual(decoded["groups"], ["research"])
            self.assertGreaterEqual(provider.jwks_requests, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_keycloak_callback_rejects_missing_tenant_claim(self) -> None:
        config = keycloak_config()
        key, jwk = rsa_key("kid-current")
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            with patch("authnode.oidc.urlopen", MockOidcProvider(config)):
                login = _open_no_redirect(
                    opener,
                    f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback",
                )
            state = parse_qs(urlsplit(login.headers["Location"]).query)["state"][0]
            nonce = server.oidc_states[state]["nonce"]
            token = oidc_token(config, key, "kid-current", nonce=nonce, overrides={"tenant_id": None})
            provider = MockOidcProvider(config, id_token=token, jwks_sequence=[{"keys": [jwk]}])

            with patch("authnode.oidc.urlopen", provider):
                with self.assertRaises(HTTPError) as blocked:
                    urlopen(f"{base_url}/oidc/callback?state={state}&code=mock-code", timeout=5)
            self.assertEqual(blocked.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_keycloak_callback_rejects_wrong_audience(self) -> None:
        config = keycloak_config()
        key, jwk = rsa_key("kid-current")
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            with patch("authnode.oidc.urlopen", MockOidcProvider(config)):
                login = _open_no_redirect(
                    opener,
                    f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback",
                )
            state = parse_qs(urlsplit(login.headers["Location"]).query)["state"][0]
            nonce = server.oidc_states[state]["nonce"]
            token = oidc_token(config, key, "kid-current", nonce=nonce, overrides={"aud": "wrong-client"})
            provider = MockOidcProvider(config, id_token=token, jwks_sequence=[{"keys": [jwk]}])

            with patch("authnode.oidc.urlopen", provider):
                with self.assertRaises(HTTPError) as blocked:
                    urlopen(f"{base_url}/oidc/callback?state={state}&code=mock-code", timeout=5)
            self.assertEqual(blocked.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_keycloak_jwks_refreshes_once_for_unknown_kid(self) -> None:
        config = keycloak_config()
        old_key, old_jwk = rsa_key("kid-old")
        new_key, new_jwk = rsa_key("kid-new")
        _ = old_key
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            with patch("authnode.oidc.urlopen", MockOidcProvider(config)):
                login = _open_no_redirect(
                    opener,
                    f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback",
                )
            state = parse_qs(urlsplit(login.headers["Location"]).query)["state"][0]
            nonce = server.oidc_states[state]["nonce"]
            token = oidc_token(config, new_key, "kid-new", nonce=nonce)
            provider = MockOidcProvider(
                config,
                id_token=token,
                jwks_sequence=[{"keys": [old_jwk]}, {"keys": [new_jwk]}],
            )

            with patch("authnode.oidc.urlopen", provider):
                callback = _open_no_redirect(opener, f"{base_url}/oidc/callback?state={state}&code=mock-code")
            self.assertEqual(callback.code, 302)
            self.assertEqual(provider.jwks_requests, 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_keycloak_logout_redirects_to_end_session_endpoint(self) -> None:
        config = keycloak_config()
        server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        opener = build_opener(NoRedirectHandler)
        try:
            with patch("authnode.oidc.urlopen", MockOidcProvider(config)):
                response = _open_no_redirect(
                    opener,
                    f"{base_url}/logout?return_to=http%3A%2F%2Fpska.local%2Flogin",
                )
            self.assertEqual(response.code, 302)
            location = response.headers["Location"]
            params = parse_qs(urlsplit(location).query)
            self.assertTrue(location.startswith("http://keycloak.test/logout?"))
            self.assertEqual(params["client_id"], ["authnode"])
            self.assertEqual(params["post_logout_redirect_uri"], ["http://pska.local/login"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_proxy_forward_headers_strip_spoofed_identity(self) -> None:
        forwarded = proxy_forward_headers(
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer attacker",
                "X-FastReAct-User-Key": "attacker",
                "X-PSKA-Tenant-Id": "evil",
                "X-AuthNode-User-Key": "attacker",
            },
            {
                "Authorization": "Bearer authnode",
                "X-FastReAct-User-Key": "pska:alice",
            },
        )

        self.assertEqual(forwarded["Content-Type"], "application/json")
        self.assertEqual(forwarded["Authorization"], "Bearer authnode")
        self.assertEqual(forwarded["X-FastReAct-User-Key"], "pska:alice")
        self.assertNotIn("X-PSKA-Tenant-Id", forwarded)
        self.assertNotIn("X-AuthNode-User-Key", forwarded)

    def test_contract_checker_passes_offline_contract(self) -> None:
        report = check_contract(self.config, user_key_or_id="pska:alice", tenant_id_or_key="tenant_a")

        self.assertTrue(report["ok"])
        self.assertEqual(report["user"]["user_key"], "pska:alice")
        self.assertIn("proxy_strips_spoofed_identity_headers", {check["name"] for check in report["checks"]})


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 - urllib hook signature.
        return None


def _open_no_redirect(opener, request):  # noqa: ANN001 - urllib opener/response test helper.
    try:
        return opener.open(request, timeout=5)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return exc
        raise


class FakeResponse:
    def __init__(self, payload: dict):
        self.status = 200
        self._body = json.dumps(payload).encode("utf-8")
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001 - context manager hook.
        return False

    def read(self):
        return self._body


class MockOidcProvider:
    def __init__(
        self,
        config: AuthNodeConfig,
        *,
        id_token: str = "unused",
        jwks_sequence: list[dict] | None = None,
    ):
        self.config = config
        self.id_token = id_token
        self.jwks_sequence = list(jwks_sequence or [{"keys": []}])
        self.jwks_requests = 0

    def __call__(self, request, timeout=0):  # noqa: ANN001 - urllib compatible fake.
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if url == f"{self.config.keycloak.issuer_url}/.well-known/openid-configuration":
            return FakeResponse(
                {
                    "issuer": self.config.keycloak.issuer_url,
                    "authorization_endpoint": "http://keycloak.test/auth",
                    "token_endpoint": "http://keycloak.test/token",
                    "jwks_uri": "http://keycloak.test/jwks",
                    "end_session_endpoint": "http://keycloak.test/logout",
                }
            )
        if url == "http://keycloak.test/token":
            payload = parse_qs(request.data.decode("utf-8"))
            if payload.get("grant_type") != ["authorization_code"] or payload.get("client_id") != ["authnode"]:
                raise AssertionError(f"unexpected token payload: {payload}")
            return FakeResponse({"access_token": "mock-access-token", "id_token": self.id_token})
        if url == "http://keycloak.test/jwks":
            self.jwks_requests += 1
            index = min(self.jwks_requests - 1, len(self.jwks_sequence) - 1)
            return FakeResponse(self.jwks_sequence[index])
        raise AssertionError(f"unexpected OIDC URL: {url}")


def keycloak_config() -> AuthNodeConfig:
    return AuthNodeConfig.from_dict(
        {
            **CONFIG_DATA,
            "browser_login_provider": "keycloak",
            "keycloak": {
                "issuer_url": "http://keycloak.test/realms/pska",
                "client_id": "authnode",
                "redirect_uri": "http://authnode.test/oidc/callback",
                "tenant_claims": ["tenant_id", "tenant_key"],
                "user_id_claims": ["preferred_username", "sub"],
                "role_claims": ["roles", "realm_access.roles"],
                "group_claims": ["groups"],
            },
        }
    )


def rsa_key(kid: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return key, jwk


def oidc_token(config: AuthNodeConfig, key, kid: str, *, nonce: str, overrides: dict | None = None):  # noqa: ANN001 - test key type.
    now = int(time.time())
    claims = {
        "iss": config.keycloak.issuer_url,
        "aud": config.keycloak.client_id,
        "sub": "keycloak-subject",
        "preferred_username": "keycloak-writer",
        "tenant_id": "tenant_oidc",
        "nonce": nonce,
        "email": "writer@example.test",
        "name": "Keycloak Writer",
        "roles": ["writer"],
        "realm_access": {"roles": ["admin"]},
        "groups": ["research"],
        "iat": now,
        "nbf": now - 5,
        "exp": now + 300,
    }
    for name, value in (overrides or {}).items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return pyjwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


if __name__ == "__main__":
    unittest.main()
