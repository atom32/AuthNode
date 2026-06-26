from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any


class JwtError(RuntimeError):
    pass


def encode_hs256(claims: dict[str, Any], secret: str) -> str:
    if not secret:
        raise JwtError("JWT secret is required")
    header = {"alg": "HS256", "typ": "JWT"}
    header_segment = _encode_segment(header)
    payload_segment = _encode_segment(claims)
    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def decode_hs256(
    token: str,
    secret: str,
    *,
    issuer: str | None = None,
    audience: str | None = None,
    verify_time: bool = True,
) -> dict[str, Any]:
    if not secret:
        raise JwtError("JWT secret is required")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("JWT must have three segments")
    header_segment, payload_segment, signature_segment = parts
    header = _decode_segment_json(header_segment)
    if header.get("alg") != "HS256":
        raise JwtError("only HS256 JWTs are supported")
    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    provided = _b64url_decode(signature_segment)
    if not hmac.compare_digest(expected, provided):
        raise JwtError("JWT signature is invalid")
    claims = _decode_segment_json(payload_segment)
    if issuer and claims.get("iss") != issuer:
        raise JwtError("JWT issuer is invalid")
    if audience:
        audiences = _list_claim(claims.get("aud"))
        if audience not in audiences:
            raise JwtError("JWT audience is invalid")
    if verify_time:
        now = datetime.now(timezone.utc).timestamp()
        if "exp" in claims and now >= float(claims["exp"]):
            raise JwtError("JWT has expired")
        if "nbf" in claims and now < float(claims["nbf"]):
            raise JwtError("JWT is not valid yet")
    return claims


def _encode_segment(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(raw)


def _decode_segment_json(segment: str) -> dict[str, Any]:
    try:
        decoded = _b64url_decode(segment)
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise JwtError("JWT segment is not valid JSON") from exc
    if not isinstance(value, dict):
        raise JwtError("JWT segment must decode to an object")
    return value


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _list_claim(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]

