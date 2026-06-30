from __future__ import annotations

import argparse
import json
import shlex
from typing import Any

from authnode.catalog import AuthCatalog
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

    iam_parser = subparsers.add_parser("iam", help="Initialize or seed the Local IAM catalog")
    iam_subparsers = iam_parser.add_subparsers(dest="iam_command", required=True)
    iam_init = iam_subparsers.add_parser("init", help="Initialize the SQLite catalog")
    iam_init.add_argument("--seed-config", action="store_true", help="Seed catalog tenants/users from authnode config")

    tenant_parser = subparsers.add_parser("tenant", help="Manage Local IAM tenants")
    tenant_subparsers = tenant_parser.add_subparsers(dest="tenant_command", required=True)
    tenant_create = tenant_subparsers.add_parser("create", help="Create or update a tenant")
    tenant_create.add_argument("tenant_id")
    tenant_create.add_argument("--tenant-key")
    tenant_create.add_argument("--name", default="")
    tenant_subparsers.add_parser("list", help="List tenants").add_argument("--include-disabled", action="store_true")
    tenant_disable = tenant_subparsers.add_parser("disable", help="Disable a tenant")
    tenant_disable.add_argument("tenant_id")
    tenant_enable = tenant_subparsers.add_parser("enable", help="Enable a disabled tenant")
    tenant_enable.add_argument("tenant_id")

    user_parser = subparsers.add_parser("user", help="Manage Local IAM users")
    user_subparsers = user_parser.add_subparsers(dest="user_command", required=True)
    user_create = user_subparsers.add_parser("create", help="Create or update a user")
    user_create.add_argument("user_id")
    user_create.add_argument("--display-name", default="")
    user_create.add_argument("--email", default="")
    user_create.add_argument("--password")
    user_subparsers.add_parser("list", help="List users").add_argument("--include-disabled", action="store_true")
    user_disable = user_subparsers.add_parser("disable", help="Disable a user")
    user_disable.add_argument("user_id")
    user_enable = user_subparsers.add_parser("enable", help="Enable a disabled user")
    user_enable.add_argument("user_id")
    user_reset = user_subparsers.add_parser("reset-password", help="Reset a user password")
    user_reset.add_argument("user_id")
    user_reset.add_argument("--password", required=True)

    membership_parser = subparsers.add_parser("membership", help="Manage Local IAM tenant memberships")
    membership_subparsers = membership_parser.add_subparsers(dest="membership_command", required=True)
    membership_add = membership_subparsers.add_parser("add", help="Add or update a membership")
    membership_add.add_argument("user_id")
    membership_add.add_argument("tenant_id")
    membership_add.add_argument("--roles", default="")
    membership_add.add_argument("--groups", default="")
    membership_remove = membership_subparsers.add_parser("remove", help="Disable a membership")
    membership_remove.add_argument("user_id")
    membership_remove.add_argument("tenant_id")
    membership_subparsers.add_parser("list", help="List tenant memberships").add_argument("--include-disabled", action="store_true")

    role_parser = subparsers.add_parser("role", help="Manage Local IAM role grants")
    role_subparsers = role_parser.add_subparsers(dest="role_command", required=True)
    role_grant = role_subparsers.add_parser("grant", help="Grant a role")
    role_grant.add_argument("user_id")
    role_grant.add_argument("tenant_id")
    role_grant.add_argument("role")
    role_revoke = role_subparsers.add_parser("revoke", help="Revoke a role")
    role_revoke.add_argument("user_id")
    role_revoke.add_argument("tenant_id")
    role_revoke.add_argument("role")

    group_parser = subparsers.add_parser("group", help="Manage Local IAM group grants")
    group_subparsers = group_parser.add_subparsers(dest="group_command", required=True)
    group_grant = group_subparsers.add_parser("grant", help="Grant a group")
    group_grant.add_argument("user_id")
    group_grant.add_argument("tenant_id")
    group_grant.add_argument("group")
    group_revoke = group_subparsers.add_parser("revoke", help="Revoke a group")
    group_revoke.add_argument("user_id")
    group_revoke.add_argument("tenant_id")
    group_revoke.add_argument("group")

    audit_parser = subparsers.add_parser("audit", help="Read Local IAM audit events")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_list = audit_subparsers.add_parser("list", help="List audit events")
    audit_list.add_argument("--limit", type=int, default=50)

    provider_parser = subparsers.add_parser("provider", help="Manage external provider account links")
    provider_subparsers = provider_parser.add_subparsers(dest="provider_command", required=True)
    provider_link = provider_subparsers.add_parser("link", help="Link an external provider subject to a local user")
    provider_link.add_argument("provider")
    provider_link.add_argument("provider_subject")
    provider_link.add_argument("user_id")
    provider_link.add_argument("tenant_id")

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
    if args.command == "iam":
        catalog = AuthCatalog(config)
        if args.iam_command == "init":
            if args.seed_config:
                catalog.seed_from_config()
            else:
                catalog.init()
            print_json({"ok": True, "catalog": str(catalog.path), "seeded": bool(args.seed_config)})
            return 0
    if args.command == "tenant":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.tenant_command == "create":
            catalog.create_tenant(args.tenant_id, tenant_key=args.tenant_key, name=args.name)
            print_json({"ok": True})
            return 0
        if args.tenant_command == "list":
            print_json({"tenants": catalog.list_tenants(include_disabled=args.include_disabled)})
            return 0
        if args.tenant_command == "disable":
            catalog.disable_tenant(args.tenant_id)
            print_json({"ok": True})
            return 0
        if args.tenant_command == "enable":
            catalog.enable_tenant(args.tenant_id)
            print_json({"ok": True})
            return 0
    if args.command == "user":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.user_command == "create":
            catalog.create_user(args.user_id, display_name=args.display_name, email=args.email, password=args.password)
            print_json({"ok": True})
            return 0
        if args.user_command == "list":
            print_json({"users": catalog.list_users(include_disabled=args.include_disabled)})
            return 0
        if args.user_command == "disable":
            catalog.disable_user(args.user_id)
            print_json({"ok": True})
            return 0
        if args.user_command == "enable":
            catalog.enable_user(args.user_id)
            print_json({"ok": True})
            return 0
        if args.user_command == "reset-password":
            catalog.set_password(args.user_id, args.password)
            print_json({"ok": True})
            return 0
    if args.command == "membership":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.membership_command == "add":
            catalog.add_membership(
                args.user_id,
                args.tenant_id,
                roles=_csv(args.roles),
                groups=_csv(args.groups),
            )
            print_json({"ok": True})
            return 0
        if args.membership_command == "remove":
            catalog.remove_membership(args.user_id, args.tenant_id)
            print_json({"ok": True})
            return 0
        if args.membership_command == "list":
            print_json({"memberships": catalog.list_memberships(include_disabled=args.include_disabled)})
            return 0
    if args.command == "role":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.role_command == "grant":
            catalog.grant_role(args.user_id, args.tenant_id, args.role)
            print_json({"ok": True})
            return 0
        if args.role_command == "revoke":
            catalog.revoke_role(args.user_id, args.tenant_id, args.role)
            print_json({"ok": True})
            return 0
    if args.command == "group":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.group_command == "grant":
            catalog.grant_group(args.user_id, args.tenant_id, args.group)
            print_json({"ok": True})
            return 0
        if args.group_command == "revoke":
            catalog.revoke_group(args.user_id, args.tenant_id, args.group)
            print_json({"ok": True})
            return 0
    if args.command == "audit":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.audit_command == "list":
            print_json({"events": catalog.list_audit(limit=args.limit)})
            return 0
    if args.command == "provider":
        catalog = AuthCatalog(config)
        catalog.init()
        if args.provider_command == "link":
            catalog.link_provider_account(
                provider=args.provider,
                provider_subject=args.provider_subject,
                user_id=args.user_id,
                tenant_id=args.tenant_id,
            )
            print_json({"ok": True})
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


def _csv(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


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
