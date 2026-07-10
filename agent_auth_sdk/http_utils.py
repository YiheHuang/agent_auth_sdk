"""HTTP 相关的纯函数工具。"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from urllib.parse import urlparse

_RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def canonical_json_bytes(value: object) -> bytes:
    """生成 v1 协议使用的确定性 UTF-8 JSON。"""

    def reject_non_finite(item: object) -> None:
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite JSON numbers are not supported")
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                reject_non_finite(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                reject_non_finite(nested)

    reject_non_finite(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not valid canonical JSON") from exc


def ensure_bytes(body: bytes | str | dict | list | None) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return canonical_json_bytes(body)


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
    return datetime.now(UTC)


def to_iso_z(ts: datetime) -> str:
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return ts.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_rfc3339_utc_seconds(value: str) -> datetime:
    """解析协议限定的 UTC RFC 3339 秒级 timestamp。"""

    if not isinstance(value, str) or not _RFC3339_UTC_SECONDS.fullmatch(value):
        raise ValueError("timestamp must use UTC RFC3339 second precision (YYYY-MM-DDTHH:MM:SSZ)")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _to_base64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def from_base64url(value: str) -> bytes:
    import base64
    import binascii

    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid base64url value")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid base64url value") from exc
