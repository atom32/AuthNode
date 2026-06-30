from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
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

from authnode.catalog import AuthCatalog, SESSION_COOKIE_NAME
from authnode.cli import main as cli_main
from authnode.config import AuthNodeConfig, load_config
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

    def test_local_iam_catalog_hashes_password_and_enforces_membership(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(tmpdir)
            catalog = AuthCatalog(config)
            catalog.seed_from_config()

            credential_hash = catalog.connect().execute(
                "SELECT password_hash FROM user_credentials WHERE user_id = ?",
                ("alice",),
            ).fetchone()["password_hash"]
            self.assertNotEqual(credential_hash, "alice-local")
            self.assertIn("$argon2", credential_hash)

            user, tenant = catalog.authenticate(username="alice", tenant_id="tenant_a", password="alice-local")
            self.assertEqual(user.user_key, "pska:alice")
            self.assertEqual(tenant.tenant_id, "tenant_a")

            with self.assertRaisesRegex(Exception, "invalid username or password|unknown catalog identity"):
                catalog.authenticate(username="alice", tenant_id="tenant_missing", password="alice-local")

            catalog.set_password("alice", "changed-local")
            with self.assertRaisesRegex(Exception, "invalid username or password"):
                catalog.authenticate(username="alice", tenant_id="tenant_a", password="alice-local")
            catalog.authenticate(username="alice", tenant_id="tenant_a", password="changed-local")

            catalog.disable_user("alice")
            with self.assertRaisesRegex(Exception, "invalid username or password"):
                catalog.authenticate(username="alice", tenant_id="tenant_a", password="changed-local")

    def test_local_iam_rate_limit_and_audit_events(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(
                tmpdir,
                {
                    "login_rate_limit": {"max_attempts": 2, "window_seconds": 300},
                },
            )
            catalog = AuthCatalog(config)
            catalog.seed_from_config()

            for _ in range(2):
                with self.assertRaisesRegex(Exception, "invalid username or password"):
                    catalog.authenticate(username="alice", tenant_id="tenant_a", password="wrong")
            with self.assertRaisesRegex(Exception, "too many login attempts"):
                catalog.authenticate(username="alice", tenant_id="tenant_a", password="alice-local")
            events = catalog.list_audit(limit=10)
            self.assertIn("login.rate_limited", {event["event_type"] for event in events})
            self.assertIn("login.failure", {event["event_type"] for event in events})

    def test_local_iam_strict_membership_disabled_user_reset_password_and_audit(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(tmpdir)
            catalog = AuthCatalog(config)
            catalog.seed_from_config()

            catalog.create_tenant("tenant_b", name="Tenant B")
            catalog.create_user("bob", password="bob-local12")

            with self.assertRaisesRegex(Exception, "invalid username or password|unknown catalog identity"):
                catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-local12")

            catalog.add_membership("bob", "tenant_b", roles=["writer"], groups=["qa"])
            user, tenant = catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-local12")
            self.assertEqual(user.user_key, "pska:bob")
            self.assertEqual(tenant.tenant_id, "tenant_b")
            self.assertEqual(user.roles, ("writer",))
            self.assertEqual(user.groups, ("qa",))

            catalog.set_password("bob", "bob-new-pass")
            with self.assertRaisesRegex(Exception, "invalid username or password"):
                catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-local12")
            catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-new-pass")

            catalog.disable_user("bob")
            with self.assertRaisesRegex(Exception, "invalid username or password"):
                catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-new-pass")
            catalog.enable_user("bob")
            catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-new-pass")

            catalog.remove_membership("bob", "tenant_b")
            with self.assertRaisesRegex(Exception, "invalid username or password|unknown catalog identity"):
                catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-new-pass")

            events = {event["event_type"] for event in catalog.list_audit(limit=50)}
            self.assertIn("user.password_set", events)
            self.assertIn("user.disable", events)
            self.assertIn("user.enable", events)
            self.assertIn("membership.disable", events)

    def test_cli_local_admin_flow_creates_login_ready_user(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "authnode.local.json"
            data = {
                **CONFIG_DATA,
                "browser_login_provider": "local_iam",
                "identity_mode": "hybrid",
                "catalog_store": {"type": "sqlite", "path": "authnode-cli.db"},
                "password_policy": {"min_length": 10},
                "tenants": [],
                "users": [],
            }
            config_path.write_text(json.dumps(data), encoding="utf-8")

            _run_cli("--config", str(config_path), "iam", "init")
            _run_cli("--config", str(config_path), "tenant", "create", "tenant_cli", "--name", "CLI Tenant")
            _run_cli(
                "--config",
                str(config_path),
                "user",
                "create",
                "cli_user",
                "--display-name",
                "CLI User",
                "--password",
                "cli-password",
            )
            _run_cli(
                "--config",
                str(config_path),
                "membership",
                "add",
                "cli_user",
                "tenant_cli",
                "--roles",
                "admin,writer",
                "--groups",
                "local",
            )
            _run_cli("--config", str(config_path), "user", "reset-password", "cli_user", "--password", "cli-new-pass")

            catalog = AuthCatalog(load_config(config_path))
            user, tenant = catalog.authenticate(username="cli_user", tenant_id="tenant_cli", password="cli-new-pass")
            self.assertEqual(user.user_key, "pska:cli_user")
            self.assertEqual(tenant.tenant_id, "tenant_cli")
            self.assertIn("admin", user.roles)
            memberships = catalog.list_memberships()
            self.assertEqual(memberships[0]["groups"], ["local"])

    def test_local_iam_browser_login_sets_authnode_session_and_reuses_it(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(tmpdir)
            server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            opener = build_opener(NoRedirectHandler)
            try:
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
                session_cookie = response.headers["Set-Cookie"]
                self.assertIn(SESSION_COOKIE_NAME, session_cookie)
                code = parse_qs(urlsplit(response.headers["Location"]).query)["code"][0]

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
                self.assertEqual(decoded["provider"], "authnode-local-iam")
                self.assertEqual(decoded["tenant_id"], "tenant_a")

                cookie_value = session_cookie.split(";", 1)[0]
                reuse_request = Request(
                    f"{base_url}/login?target=pska&return_to=http%3A%2F%2Fpska.local%2Fauth%2Fcallback&next=%2Freuse",
                    headers={"Cookie": cookie_value},
                )
                reused = _open_no_redirect(opener, reuse_request)
                self.assertEqual(reused.code, 302)
                self.assertEqual(parse_qs(urlsplit(reused.headers["Location"]).query)["next"], ["/reuse"])

                logout = _open_no_redirect(opener, Request(f"{base_url}/logout?return_to=http%3A%2F%2Fpska.local%2Flogin", headers={"Cookie": cookie_value}))
                self.assertEqual(logout.code, 302)
                self.assertIn(f"{SESSION_COOKIE_NAME}=;", logout.headers["Set-Cookie"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_local_iam_provider_account_can_bind_external_identity_to_membership(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(tmpdir)
            catalog = AuthCatalog(config)
            catalog.seed_from_config()
            catalog.link_provider_account(
                provider="keycloak",
                provider_subject="external-subject",
                user_id="alice",
                tenant_id="tenant_a",
            )

            user, tenant = catalog.resolve_provider_identity(
                provider="keycloak",
                provider_subject="external-subject",
                fallback_user_id="ignored",
                tenant_id="tenant_a",
            )
            self.assertEqual(user.user_key, "pska:alice")
            self.assertEqual(tenant.tenant_id, "tenant_a")

    def test_local_iam_management_api_requires_admin_and_manages_catalog(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(tmpdir, {"admin_token": "admin-secret", "strict_identity": True})
            server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            headers = {"X-AuthNode-Admin-Token": "admin-secret"}
            try:
                with self.assertRaises(HTTPError) as blocked:
                    urlopen(f"{base_url}/v1/iam/tenants", timeout=5)
                self.assertEqual(blocked.exception.code, 401)

                _json_request(
                    f"{base_url}/v1/iam/tenants",
                    {"tenant_id": "tenant_b", "name": "Tenant B"},
                    headers=headers,
                )
                _json_request(
                    f"{base_url}/v1/iam/users",
                    {"user_id": "bob", "display_name": "Bob", "password": "bob-local12"},
                    headers=headers,
                )
                _json_request(
                    f"{base_url}/v1/iam/memberships",
                    {"user_id": "bob", "tenant_id": "tenant_b", "roles": ["writer"], "groups": ["qa"]},
                    headers=headers,
                )
                _json_request(
                    f"{base_url}/v1/iam/roles",
                    {"user_id": "bob", "tenant_id": "tenant_b", "role": "reviewer"},
                    headers=headers,
                )
                _json_request(
                    f"{base_url}/v1/iam/groups",
                    {"user_id": "bob", "tenant_id": "tenant_b", "group": "review"},
                    headers=headers,
                )
                _json_request(
                    f"{base_url}/v1/iam/users/bob/password",
                    {"password": "bob-new-pass"},
                    headers=headers,
                )

                with urlopen(Request(f"{base_url}/v1/iam/users", headers=headers), timeout=5) as response:
                    users = json.loads(response.read().decode("utf-8"))["users"]
                self.assertIn("bob", {user["user_id"] for user in users})

                catalog_user, catalog_tenant = server.catalog.resolve_identity(user_key_or_id="bob", tenant_id="tenant_b")
                self.assertEqual(catalog_user.user_key, "pska:bob")
                self.assertEqual(catalog_tenant.tenant_id, "tenant_b")
                self.assertIn("writer", catalog_user.roles)
                self.assertIn("reviewer", catalog_user.roles)
                self.assertIn("qa", catalog_user.groups)
                self.assertIn("review", catalog_user.groups)
                server.catalog.authenticate(username="bob", tenant_id="tenant_b", password="bob-new-pass")

                _json_request(
                    f"{base_url}/v1/iam/memberships",
                    {"user_id": "bob", "tenant_id": "tenant_b"},
                    headers=headers,
                    method="DELETE",
                )
                with self.assertRaisesRegex(Exception, "unknown catalog identity"):
                    server.catalog.resolve_identity(user_key_or_id="bob", tenant_id="tenant_b")
                _json_request(
                    f"{base_url}/v1/iam/memberships",
                    {"user_id": "bob", "tenant_id": "tenant_b", "roles": ["writer"], "groups": ["qa"]},
                    headers=headers,
                )

                _json_request(f"{base_url}/v1/iam/users/bob/disable", {}, headers=headers)
                with self.assertRaisesRegex(Exception, "unknown catalog identity"):
                    server.catalog.resolve_identity(user_key_or_id="bob", tenant_id="tenant_b")
                _json_request(f"{base_url}/v1/iam/users/bob/enable", {}, headers=headers)
                server.catalog.resolve_identity(user_key_or_id="bob", tenant_id="tenant_b")

                with urlopen(Request(f"{base_url}/v1/iam/memberships?include_disabled=1", headers=headers), timeout=5) as response:
                    memberships = json.loads(response.read().decode("utf-8"))["memberships"]
                self.assertIn("bob", {item["user_id"] for item in memberships})

                with urlopen(Request(f"{base_url}/v1/iam/audit?limit=20", headers=headers), timeout=5) as response:
                    events = json.loads(response.read().decode("utf-8"))["events"]
                event_types = {event["event_type"] for event in events}
                self.assertIn("membership.upsert", event_types)
                self.assertIn("user.password_set", event_types)
                self.assertIn("user.disable", event_types)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_local_admin_ui_uses_http_only_session_and_creates_login_identity(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config = local_iam_config(tmpdir, {"admin_token": "admin-secret", "strict_identity": True})
            server = AuthNodeHTTPServer(("127.0.0.1", 0), AuthNodeHandler, config)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            opener = build_opener(NoRedirectHandler)
            try:
                blocked = _open_no_redirect(opener, f"{base_url}/admin")
                self.assertEqual(blocked.code, 302)
                self.assertEqual(blocked.headers["Location"], "/admin/login")

                with urlopen(f"{base_url}/admin/login", timeout=5) as response:
                    login_page = response.read().decode("utf-8")
                self.assertIn("AuthNode Admin", login_page)
                self.assertNotIn("admin-secret", login_page)

                login_body = urlencode({"admin_token": "admin-secret"}).encode()
                login_request = Request(
                    f"{base_url}/admin/login",
                    data=login_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                )
                login = _open_no_redirect(opener, login_request)
                self.assertEqual(login.code, 302)
                admin_cookie = login.headers["Set-Cookie"]
                self.assertIn("authnode_admin=", admin_cookie)
                self.assertIn("HttpOnly", admin_cookie)
                self.assertNotIn("admin-secret", admin_cookie)
                cookie_header = admin_cookie.split(";", 1)[0]

                with urlopen(Request(f"{base_url}/admin", headers={"Cookie": cookie_header}), timeout=5) as response:
                    admin_page = response.read().decode("utf-8")
                self.assertIn("Local IAM catalog", admin_page)
                self.assertNotIn("admin-secret", admin_page)

                _post_form_no_redirect(
                    opener,
                    f"{base_url}/admin/action",
                    {
                        "action": "tenant.create",
                        "tenant_id": "tenant_ui",
                        "name": "UI Tenant",
                    },
                    cookie_header,
                )
                _post_form_no_redirect(
                    opener,
                    f"{base_url}/admin/action",
                    {
                        "action": "user.create",
                        "user_id": "ui_user",
                        "display_name": "UI User",
                        "password": "ui-password1",
                    },
                    cookie_header,
                )
                _post_form_no_redirect(
                    opener,
                    f"{base_url}/admin/action",
                    {
                        "action": "membership.save",
                        "user_id": "ui_user",
                        "tenant_id": "tenant_ui",
                        "roles": "writer",
                        "groups": "local",
                    },
                    cookie_header,
                )

                user, tenant = server.catalog.authenticate(username="ui_user", tenant_id="tenant_ui", password="ui-password1")
                self.assertEqual(user.user_key, "pska:ui_user")
                self.assertEqual(tenant.tenant_id, "tenant_ui")

                login_body = urlencode(
                    {
                        "username": "ui_user",
                        "tenant_id": "tenant_ui",
                        "password": "ui-password1",
                        "target": "pska",
                        "return_to": "http://pska.local/auth/callback",
                    }
                ).encode()
                request = Request(
                    f"{base_url}/login",
                    data=login_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                )
                response = _open_no_redirect(opener, request)
                self.assertEqual(response.code, 302)
                self.assertIn("code=", response.headers["Location"])
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


def _post_form_no_redirect(opener, url: str, payload: dict[str, str], cookie: str):  # noqa: ANN001 - urllib opener test helper.
    request = Request(
        url,
        data=urlencode(payload).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        method="POST",
    )
    response = _open_no_redirect(opener, request)
    if response.code not in {302, 303}:
        raise AssertionError(f"unexpected response: {response.code}")
    return response


def _json_request(url: str, payload: dict, *, headers: dict[str, str], method: str = "POST") -> dict:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method=method,
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _run_cli(*argv: str) -> dict:
    output = io.StringIO()
    with redirect_stdout(output):
        code = cli_main(list(argv))
    if code != 0:
        raise AssertionError(f"CLI exited with {code}: {argv}")
    text = output.getvalue()
    return json.loads(text) if text.strip() else {}


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


def local_iam_config(tmpdir: str, extra: dict | None = None) -> AuthNodeConfig:
    data = {
        **CONFIG_DATA,
        "browser_login_provider": "local_iam",
        "identity_mode": "hybrid",
        "strict_membership": True,
        "session_ttl_seconds": 600,
        "catalog_store": {"type": "sqlite", "path": "authnode-test.db"},
        "password_policy": {"min_length": 10},
    }
    data.update(extra or {})
    return AuthNodeConfig.from_dict(data, source_path=Path(tmpdir) / "authnode.test.json")


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
