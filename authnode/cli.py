from __future__ import annotations

import argparse
import json
import shlex
from typing import Any

from authnode.contract import check_contract
from authnode.config import load_config
from authnode.identity import (
    issue_identity_token,
    public_tenant,
    public_user,
    token_response,
    trusted_headers_for_user,
)
from authnode.server import serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authnode")
    parser.add_argument("--config", help="Path to authnode.local.json")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Run the local auth broker")
    serve_parser.add_argument("--host")
    serve_parser.add_argument("--port", type=int)

    token_parser = subparsers.add_parser("token", help="Issue an HS256 JWT for a local user")
    token_parser.add_argument("user", nargs="?", help="user_key or user_id; defaults to first configured user")
    token_parser.add_argument("--tenant")
    token_parser.add_argument("--audience", help="Comma separated audiences")
    token_parser.add_argument("--ttl-seconds", type=int)
    token_parser.add_argument("--raw", action="store_true", help="Print token only")

    headers_parser = subparsers.add_parser("headers", help="Print trusted headers or Authorization header")
    headers_parser.add_argument("user", nargs="?")
    headers_parser.add_argument("--tenant")
    headers_parser.add_argument("--target", choices=["fastreact", "pska", "both"], default="both")
    headers_parser.add_argument("--mode", choices=["trusted_headers", "jwt"], default="trusted_headers")
    headers_parser.add_argument("--curl", action="store_true", help="Print curl -H arguments")

    subparsers.add_parser("users", help="List configured local users")
    subparsers.add_parser("tenants", help="List configured local tenants")

    env_parser = subparsers.add_parser("env", help="Print FastReAct and PSKA auth environment exports")
    env_parser.add_argument("--mode", choices=["jwt", "trusted_headers"], default="jwt")

    contract_parser = subparsers.add_parser("contract", help="Check the AuthNode/FastReAct/PSKA identity contract")
    contract_parser.add_argument("user", nargs="?")
    contract_parser.add_argument("--tenant")
    contract_parser.add_argument("--fastreact-url")
    contract_parser.add_argument("--pska-url")
    contract_parser.add_argument("--live", action="store_true", help="Run live HTTP checks for provided service URLs")
    contract_parser.add_argument(
        "--fastreact-chat",
        action="store_true",
        help="In live mode, call FastReAct /v1/chat/completions with the issued JWT",
    )
    contract_parser.add_argument("--timeout-seconds", type=int, default=10)

    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.command == "serve":
        serve(config, host=args.host, port=args.port)
        return 0
    if args.command == "token":
        token, claims = issue_identity_token(
            config,
            args.user,
            tenant_id_or_key=args.tenant,
            audience=args.audience,
            ttl_seconds=args.ttl_seconds,
        )
        if args.raw:
            print(token)
        else:
            print_json(token_response(token, claims))
        return 0
    if args.command == "headers":
        if args.mode == "jwt":
            token, claims = issue_identity_token(
                config,
                args.user,
                tenant_id_or_key=args.tenant,
                audience=None if args.target == "both" else args.target,
            )
            payload: dict[str, Any] = {"headers": {"Authorization": f"Bearer {token}"}, "claims": claims}
        else:
            payload = {"headers": trusted_headers_for_user(config, args.user, tenant_id_or_key=args.tenant, target=args.target)}
        if args.curl:
            for key, value in payload["headers"].items():
                print(f"-H {shlex.quote(f'{key}: {value}')}")
        else:
            print_json(payload)
        return 0
    if args.command == "users":
        print_json({"users": [public_user(user) for user in config.users]})
        return 0
    if args.command == "tenants":
        print_json({"tenants": [public_tenant(tenant) for tenant in config.tenants]})
        return 0
    if args.command == "env":
        print_env(config.jwt_secret, config.issuer, args.mode)
        return 0
    if args.command == "contract":
        report = check_contract(
            config,
            user_key_or_id=args.user,
            tenant_id_or_key=args.tenant,
            fastreact_url=args.fastreact_url,
            pska_url=args.pska_url,
            live=args.live,
            fastreact_chat=args.fastreact_chat,
            timeout_seconds=args.timeout_seconds,
        )
        print_json(report)
        return 0 if report["ok"] else 1
    return 1


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def print_env(secret: str, issuer: str, mode: str) -> None:
    if mode == "trusted_headers":
        lines = [
            ("FASTREACT_AUTH_MODE", "trusted_headers"),
            ("PSKA_AUTH_MODE", "trusted_headers"),
        ]
    else:
        lines = [
            ("FASTREACT_AUTH_MODE", "jwt"),
            ("FASTREACT_AUTH_JWT_SECRET", secret),
            ("FASTREACT_AUTH_JWT_ISSUER", issuer),
            ("FASTREACT_AUTH_JWT_AUDIENCE", "fastreact"),
            ("FASTREACT_AUTH_JWT_TENANT_CLAIMS", "tenant_key,tenant_id,tenant,org_id"),
            ("PSKA_AUTH_MODE", "jwt"),
            ("PSKA_AUTH_JWT_SECRET", secret),
            ("PSKA_AUTH_JWT_ISSUER", issuer),
            ("PSKA_AUTH_JWT_AUDIENCE", "pska"),
            ("PSKA_AUTH_JWT_TENANT_CLAIMS", "tenant_id,tenant_key,tenant,org_id"),
        ]
    for key, value in lines:
        print(f"export {key}={shlex.quote(value)}")


if __name__ == "__main__":
    raise SystemExit(main())
