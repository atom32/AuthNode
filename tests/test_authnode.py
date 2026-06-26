from __future__ import annotations

import unittest
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from authnode.config import AuthNodeConfig
from authnode.contract import check_contract
from authnode.identity import issue_identity_token, trusted_headers_for_user
from authnode.jwt import decode_hs256
from authnode.server import AuthNodeHTTPServer, AuthNodeHandler, proxy_forward_headers


CONFIG_DATA = {
    "jwt_secret": "test-secret",
    "issuer": "authnode.test",
    "tenants": [{"tenant_id": "tenant_a", "tenant_key": "tenant_a"}],
    "users": [
        {
            "user_id": "alice",
            "user_key": "pska:alice",
            "tenant_id": "tenant_a",
            "tenant_key": "tenant_a",
            "display_name": "Alice",
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


if __name__ == "__main__":
    unittest.main()
