"""请求验签逻辑。"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import TEST_PROFILE, VerificationConfig
from .crypto import verify_signature
from .errors import VerificationErrorCode
from .http_utils import build_canonical_request, canonicalize_headers
from .identity import parse_agent_id
from .metadata import resolve_agent, select_verification_key
from .models import VerificationFailure, VerificationSuccess
from .stores import MetadataCache, NonceStore


def _failure(code: VerificationErrorCode, reason: str) -> VerificationFailure:
    return VerificationFailure(code=code.value, reason=reason)


async def verify_http_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | str | dict | list | None,
    nonce_store: NonceStore,
    http_client: httpx.AsyncClient,
    cache: MetadataCache | None = None,
    config: VerificationConfig | None = None,
    now: datetime | None = None,
    request_id: str | None = None,
) -> VerificationSuccess | VerificationFailure:
    config = config or VerificationConfig(profile=TEST_PROFILE)
    profile = config.profile
    normalized_headers = canonicalize_headers(headers)
    agent_id = normalized_headers.get("x-agent-id")
    kid = normalized_headers.get("x-agent-kid")
    timestamp = normalized_headers.get("x-agent-timestamp")
    nonce = normalized_headers.get("x-agent-nonce")
    signature = normalized_headers.get("x-agent-signature")

    if config.require_signature_input_header and "x-agent-signature-input" not in normalized_headers:
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Missing x-agent-signature-input")

    if not all([agent_id, kid, timestamp, nonce, signature]):
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Missing required signature headers")

    try:
        parse_agent_id(agent_id)
    except Exception as exc:
        return _failure(VerificationErrorCode.INVALID_AGENT_ID, str(exc))

    current = now or datetime.now(timezone.utc)
    try:
        request_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Invalid timestamp format")

    if abs((current - request_time).total_seconds()) > profile.clock_skew_seconds:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Request timestamp is outside allowed skew")

    nonce_key = f"{agent_id}:{nonce}"
    if await nonce_store.has(nonce_key):
        return _failure(VerificationErrorCode.NONCE_REPLAYED, "Nonce has already been used")

    try:
        resolved = await resolve_agent(agent_id, profile=profile, http_client=http_client, cache=cache)
    except Exception as exc:
        return _failure(VerificationErrorCode.METADATA_FETCH_FAILED, str(exc))

    try:
        key = select_verification_key(resolved.metadata, kid=kid, now=current)
    except Exception as exc:
        reason = str(exc)
        if "revoked" in reason:
            return _failure(VerificationErrorCode.KEY_REVOKED, reason)
        if "expired" in reason:
            return _failure(VerificationErrorCode.KEY_EXPIRED, reason)
        return _failure(VerificationErrorCode.KEY_NOT_FOUND, reason)

    canonical, _ = build_canonical_request(
        method=method,
        url=url,
        body=body,
        agent_id=agent_id,
        kid=kid,
        timestamp=timestamp,
        nonce=nonce,
        host=normalized_headers.get("host"),
    )
    verified = verify_signature(
        public_key_pem=key.public_key_pem,
        public_key_base64url=key.public_key_base64url,
        data=canonical.encode("utf-8"),
        signature_base64url=signature,
    )
    if not verified:
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Signature verification failed")

    await nonce_store.set(nonce_key, profile.nonce_ttl_seconds)
    return VerificationSuccess(
        agent_id=agent_id,
        kid=kid,
        metadata=resolved.metadata,
        canonical=canonical,
        request_id=request_id,
    )


def verify_http_request_sync(**kwargs: Any) -> VerificationSuccess | VerificationFailure:
    return asyncio.run(verify_http_request(**kwargs))
