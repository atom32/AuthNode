from __future__ import annotations

from dataclasses import dataclass, field
import base64
import hashlib
import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt as pyjwt

from authnode.config import AuthNodeConfig, KeycloakConfig, Tenant, User


class OidcError(ValueError):
    pass


@dataclass(slots=True)
class OidcCache:
    discovery: dict[str, Any] | None = None
    jwks: dict[str, Any] | None = None
    discovery_fetched_at: float = 0
    jwks_fetched_at: float = 0


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    user: User
    tenant: Tenant
    claims: dict[str, Any] = field(default_factory=dict)


def authorization_url(config: AuthNodeConfig, cache: OidcCache, *, state: str, nonce: str, code_challenge: str) -> str:
    keycloak = _validated_keycloak(config.keycloak)
    discovery = discover(config, cache)
    endpoint = str(discovery.get("authorization_endpoint") or "")
    if not endpoint:
        raise OidcError("Keycloak discovery returned no authorization_endpoint")
    params = {
        "response_type": "code",
        "client_id": keycloak.client_id,
        "redirect_uri": keycloak.redirect_uri,
        "scope": " ".join(keycloak.scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{endpoint}?{urlencode(params)}"


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def exchange_code_for_identity(
    config: AuthNodeConfig,
    cache: OidcCache,
    *,
    code: str,
    code_verifier: str,
    nonce: str,
    timeout: float = 15,
) -> OidcIdentity:
    keycloak = _validated_keycloak(config.keycloak)
    discovery = discover(config, cache)
    token_endpoint = str(discovery.get("token_endpoint") or "")
    if not token_endpoint:
        raise OidcError("Keycloak discovery returned no token_endpoint")
    payload = {
        "grant_type": "authorization_code",
        "client_id": keycloak.client_id,
        "code": code,
        "redirect_uri": keycloak.redirect_uri,
        "code_verifier": code_verifier,
    }
    client_secret = _client_secret(keycloak)
    if client_secret:
        payload["client_secret"] = client_secret
    request = Request(
        token_endpoint,
        data=urlencode(payload).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            token_response = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OidcError(f"Keycloak token exchange failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise OidcError(f"Keycloak token exchange unavailable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise OidcError("Keycloak token exchange timed out") from exc
    except json.JSONDecodeError as exc:
        raise OidcError("Keycloak token exchange returned invalid JSON") from exc
    if not isinstance(token_response, dict):
        raise OidcError("Keycloak token exchange returned invalid payload")
    token = str(token_response.get("id_token") or token_response.get("access_token") or "")
    if not token:
        raise OidcError("Keycloak token exchange returned no id_token or access_token")
    claims = verify_token(config, cache, token=token, nonce=nonce, timeout=timeout)
    return identity_from_claims(config, claims)


def verify_token(
    config: AuthNodeConfig,
    cache: OidcCache,
    *,
    token: str,
    nonce: str | None = None,
    timeout: float = 15,
) -> dict[str, Any]:
    keycloak = _validated_keycloak(config.keycloak)
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as exc:
        raise OidcError(f"Keycloak token header is invalid: {exc}") from exc
    algorithm = str(header.get("alg") or "")
    if algorithm not in {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}:
        raise OidcError(f"Keycloak token algorithm is not allowed: {algorithm}")
    key = _signing_key(config, cache, header, timeout=timeout, force_refresh=False)
    try:
        claims = pyjwt.decode(
            token,
            key=key,
            algorithms=[algorithm],
            audience=keycloak.client_id,
            issuer=keycloak.issuer_url,
        )
    except pyjwt.PyJWTError as exc:
        raise OidcError(f"Keycloak token validation failed: {exc}") from exc
    if nonce is not None and str(claims.get("nonce") or "") != nonce:
        raise OidcError("Keycloak token nonce is invalid")
    return dict(claims)


def identity_from_claims(config: AuthNodeConfig, claims: dict[str, Any]) -> OidcIdentity:
    keycloak = _validated_keycloak(config.keycloak)
    tenant_id = _first_claim(claims, keycloak.tenant_claims)
    if not tenant_id:
        raise OidcError("Keycloak token is missing tenant claim")
    user_id = _first_claim(claims, keycloak.user_id_claims)
    if not user_id:
        raise OidcError("Keycloak token is missing user claim")
    user_key = _first_claim(claims, keycloak.user_key_claims) if keycloak.user_key_claims else ""
    if not user_key:
        user_key = user_id if ":" in user_id else f"pska:{user_id}"
    tenant = config.tenant_for(tenant_id)
    roles = tuple(_claim_values(claims, keycloak.role_claims))
    groups = tuple(_claim_values(claims, keycloak.group_claims))
    display_name = str(claims.get("name") or claims.get("preferred_username") or user_id)
    email = str(claims.get("email") or "")
    user = User(
        user_id=user_id.removeprefix("pska:"),
        user_key=user_key,
        tenant_id=tenant.tenant_id,
        tenant_key=tenant.tenant_key,
        display_name=display_name,
        email=email,
        roles=roles,
        groups=groups,
        provider="keycloak",
    )
    return OidcIdentity(user=user, tenant=tenant, claims=dict(claims))


def discover(config: AuthNodeConfig, cache: OidcCache, *, force_refresh: bool = False, timeout: float = 15) -> dict[str, Any]:
    keycloak = _validated_keycloak(config.keycloak)
    if cache.discovery and not force_refresh:
        return cache.discovery
    url = f"{keycloak.issuer_url}/.well-known/openid-configuration"
    data = _fetch_json(url, timeout=timeout)
    issuer = str(data.get("issuer") or "").rstrip("/")
    if issuer != keycloak.issuer_url:
        raise OidcError("Keycloak discovery issuer does not match configured issuer_url")
    cache.discovery = data
    cache.discovery_fetched_at = time.time()
    return data


def logout_url(config: AuthNodeConfig, cache: OidcCache, *, return_to: str) -> str:
    keycloak = _validated_keycloak(config.keycloak)
    discovery = discover(config, cache)
    endpoint = str(discovery.get("end_session_endpoint") or "")
    if not endpoint:
        return return_to
    params = {"client_id": keycloak.client_id}
    if return_to:
        params["post_logout_redirect_uri"] = return_to
    return f"{endpoint}?{urlencode(params)}"


def _signing_key(
    config: AuthNodeConfig,
    cache: OidcCache,
    header: dict[str, Any],
    *,
    timeout: float,
    force_refresh: bool,
) -> Any:
    kid = str(header.get("kid") or "")
    jwks = _jwks(config, cache, timeout=timeout, force_refresh=force_refresh)
    for item in jwks.get("keys", []):
        if not isinstance(item, dict):
            continue
        if kid and str(item.get("kid") or "") != kid:
            continue
        return pyjwt.PyJWK.from_dict(item).key
    if not force_refresh:
        return _signing_key(config, cache, header, timeout=timeout, force_refresh=True)
    raise OidcError(f"Keycloak JWKS does not contain signing key kid={kid!r}")


def _jwks(config: AuthNodeConfig, cache: OidcCache, *, timeout: float, force_refresh: bool = False) -> dict[str, Any]:
    if cache.jwks and not force_refresh:
        return cache.jwks
    discovery = discover(config, cache, timeout=timeout)
    jwks_uri = str(discovery.get("jwks_uri") or "")
    if not jwks_uri:
        raise OidcError("Keycloak discovery returned no jwks_uri")
    data = _fetch_json(jwks_uri, timeout=timeout)
    if not isinstance(data.get("keys"), list):
        raise OidcError("Keycloak JWKS returned no keys")
    cache.jwks = data
    cache.jwks_fetched_at = time.time()
    return data


def _fetch_json(url: str, *, timeout: float) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OidcError(f"OIDC request failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise OidcError(f"OIDC request unavailable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise OidcError("OIDC request timed out") from exc
    except json.JSONDecodeError as exc:
        raise OidcError("OIDC request returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise OidcError("OIDC request returned invalid payload")
    return data


def _validated_keycloak(config: KeycloakConfig) -> KeycloakConfig:
    if not config.issuer_url:
        raise OidcError("keycloak.issuer_url is required")
    if not config.client_id:
        raise OidcError("keycloak.client_id is required")
    if not config.redirect_uri:
        raise OidcError("keycloak.redirect_uri is required")
    return config


def _client_secret(config: KeycloakConfig) -> str:
    env_name = config.client_secret_env
    return os.getenv(env_name, "").strip() if env_name else ""


def _first_claim(claims: dict[str, Any], paths: tuple[str, ...]) -> str:
    for path in paths:
        values = _claim_values(claims, (path,))
        if values:
            return values[0]
    return ""


def _claim_values(claims: dict[str, Any], paths: tuple[str, ...]) -> list[str]:
    result: list[str] = []
    for path in paths:
        value = _claim_path(claims, path)
        if value is None:
            continue
        if isinstance(value, str):
            parts = [item.strip() for item in value.split(",") if item.strip()]
            result.extend(parts or [value.strip()])
        elif isinstance(value, (list, tuple, set)):
            result.extend(str(item).strip() for item in value if str(item).strip())
        else:
            result.append(str(value).strip())
    deduped: list[str] = []
    for item in result:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def _claim_path(claims: dict[str, Any], path: str) -> Any:
    current: Any = claims
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        return None
    return current
