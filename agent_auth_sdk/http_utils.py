"""HTTP 相关的纯函数工具。"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse


def ensure_bytes(body: bytes | str | dict | list | None) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha256_base64url(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return _to_base64url(digest)


def canonicalize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return {key.lower(): value for key, value in (headers or {}).items()}


def normalize_host(url: str, headers: dict[str, str] | None = None) -> str:
    lowered = canonicalize_headers(headers)
    if "host" in lowered:
        return lowered["host"]
    return urlparse(url).netloc


def build_canonical_request(
    *,
    method: str,
    url: str,
    body: bytes | str | dict | list | None,
    agent_id: str,
    kid: str,
    timestamp: str,
    nonce: str,
    host: str | None = None,
) -> tuple[str, str]:
    """构造稳定的签名原文和 body 摘要。"""

    parsed = urlparse(url)
    body_digest = sha256_base64url(ensure_bytes(body))
    path_with_query = parsed.path or "/"
    if parsed.query:
        path_with_query = f"{path_with_query}?{parsed.query}"
    request_host = host or parsed.netloc
    canonical = "\n".join(
        [
            method.upper(),
            path_with_query,
            body_digest,
            f"x-agent-id:{agent_id}",
            f"x-agent-kid:{kid}",
            f"x-agent-timestamp:{timestamp}",
            f"x-agent-nonce:{nonce}",
            f"host:{request_host}",
        ],
    )
    return canonical, body_digest


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso_z(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _to_base64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def from_base64url(value: str) -> bytes:
    import base64

    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)

