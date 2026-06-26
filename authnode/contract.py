from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from authnode.config import AuthNodeConfig
from authnode.identity import issue_identity_token, trusted_headers_for_user
from authnode.jwt import decode_hs256
from authnode.server import proxy_forward_headers


def check_contract(
    config: AuthNodeConfig,
    *,
    user_key_or_id: str | None = None,
    tenant_id_or_key: str | None = None,
    fastreact_url: str | None = None,
    pska_url: str | None = None,
    live: bool = False,
    fastreact_chat: bool = False,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    user = config.user_for(user_key_or_id, tenant_id_or_key=tenant_id_or_key)
    tenant = config.tenant_for(tenant_id_or_key or user.tenant_id or user.tenant_key)

    fastreact_token, fastreact_claims = issue_identity_token(
        config,
        user.user_key,
        tenant_id_or_key=tenant.tenant_key,
        audience="fastreact",
    )
    pska_token, pska_claims = issue_identity_token(
        config,
        user.user_key,
        tenant_id_or_key=tenant.tenant_id,
        audience="pska",
    )

    _check(
        checks,
        "fastreact_jwt_audience",
        lambda: decode_hs256(fastreact_token, config.jwt_secret, issuer=config.issuer, audience="fastreact"),
        detail="AuthNode issues aud=fastreact JWT accepted by local verifier.",
    )
    _check(
        checks,
        "pska_jwt_audience",
        lambda: decode_hs256(pska_token, config.jwt_secret, issuer=config.issuer, audience="pska"),
        detail="AuthNode issues aud=pska JWT accepted by local verifier.",
    )
    _expect(
        checks,
        "shared_subject",
        fastreact_claims["sub"] == pska_claims["sub"] == user.user_key,
        f"sub={user.user_key}",
    )
    _expect(
        checks,
        "tenant_claim_aliases",
        fastreact_claims["tenant_key"] == tenant.tenant_key and pska_claims["tenant_id"] == tenant.tenant_id,
        f"tenant_key={tenant.tenant_key}, tenant_id={tenant.tenant_id}",
    )
    _expect(
        checks,
        "metadata_claims",
        all(key in fastreact_claims and key in pska_claims for key in ["roles", "groups", "email", "name"]),
        "roles/groups/email/name are present for both services.",
    )

    headers = trusted_headers_for_user(config, user.user_key, tenant_id_or_key=tenant.tenant_id, target="both")
    _expect(
        checks,
        "trusted_header_mapping",
        headers.get("X-FastReAct-User-Key") == user.user_key
        and headers.get("X-FastReAct-Tenant-Key") == tenant.tenant_key
        and headers.get("X-PSKA-User-Id") == user.user_id
        and headers.get("X-PSKA-Tenant-Id") == tenant.tenant_id,
        "FastReAct and PSKA identity headers map to the same catalog entry.",
    )

    forwarded = proxy_forward_headers(
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer attacker",
            "X-FastReAct-User-Key": "attacker",
            "X-FastReAct-Tenant-Key": "evil",
            "X-PSKA-User-Id": "attacker",
            "X-AuthNode-User-Key": "attacker",
        },
        {
            "Authorization": f"Bearer {fastreact_token}",
            "X-FastReAct-User-Key": user.user_key,
            "X-FastReAct-Tenant-Key": tenant.tenant_key,
        },
    )
    _expect(
        checks,
        "proxy_strips_spoofed_identity_headers",
        forwarded.get("X-FastReAct-User-Key") == user.user_key
        and forwarded.get("X-FastReAct-Tenant-Key") == tenant.tenant_key
        and forwarded.get("Authorization") == f"Bearer {fastreact_token}"
        and "X-PSKA-User-Id" not in forwarded
        and "X-AuthNode-User-Key" not in forwarded,
        "Proxy preserves ordinary headers but replaces caller identity with AuthNode identity.",
    )

    if live:
        if pska_url:
            _check(
                checks,
                "pska_ready_with_jwt",
                lambda: _http_json(
                    "GET",
                    _join_url(pska_url, "/ready"),
                    headers={"Authorization": f"Bearer {pska_token}"},
                    timeout_seconds=timeout_seconds,
                ),
                detail="PSKA accepted the same identity context for /ready.",
            )
        if fastreact_url and fastreact_chat:
            _check(
                checks,
                "fastreact_chat_completions_with_jwt",
                lambda: _http_json(
                    "POST",
                    _join_url(fastreact_url, "/v1/chat/completions"),
                    headers={"Authorization": f"Bearer {fastreact_token}"},
                    payload={
                        "messages": [
                            {
                                "role": "user",
                                "content": "AuthNode contract smoke test. Reply with ok.",
                            }
                        ],
                        "user_key": user.user_key,
                        "metadata": {
                            "tenant_key": tenant.tenant_key,
                            "auth_contract_check": True,
                        },
                        "stream": False,
                    },
                    timeout_seconds=timeout_seconds,
                ),
                detail="FastReAct accepted aud=fastreact JWT on /v1/chat/completions.",
            )

    return {
        "ok": all(check["ok"] for check in checks),
        "user": {
            "user_id": user.user_id,
            "user_key": user.user_key,
            "tenant_id": tenant.tenant_id,
            "tenant_key": tenant.tenant_key,
        },
        "checks": checks,
    }


def _check(checks: list[dict[str, Any]], name: str, operation: Any, *, detail: str) -> None:
    try:
        operation()
    except Exception as exc:
        checks.append({"name": name, "ok": False, "detail": str(exc)})
        return
    checks.append({"name": name, "ok": True, "detail": detail})


def _expect(checks: list[dict[str, Any]], name: str, condition: bool, detail: str) -> None:
    checks.append({"name": name, "ok": bool(condition), "detail": detail if condition else "contract expectation failed"})


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
    timeout_seconds: int,
) -> dict[str, Any]:
    body = None
    request_headers = {"accept": "application/json", **headers}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["content-type"] = "application/json; charset=utf-8"
    request = Request(url, data=body, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"unavailable: {exc.reason}") from exc
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("response was not a JSON object")
    return value


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"

