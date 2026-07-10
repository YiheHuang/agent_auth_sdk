"""请求验签逻辑。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx

from .config import MetadataResolverConfig, VerificationConfig
from .crypto import verify_signature
from .errors import VerificationErrorCode
from .http_utils import build_canonical_request, canonicalize_headers, parse_rfc3339_utc_seconds
from .identity import parse_agent_id
from .metadata import resolve_agent, select_verification_key
from .models import VerificationFailure, VerificationSuccess
from .signing import SIGNATURE_INPUT
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
    resolver_config: MetadataResolverConfig | None = None,
    now: datetime | None = None,
    request_id: str | None = None,
) -> VerificationSuccess | VerificationFailure:
    config = config or VerificationConfig()
    profile = config.profile
    normalized_headers = canonicalize_headers(headers)
    agent_id = normalized_headers.get("x-agent-id")
    kid = normalized_headers.get("x-agent-kid")
    timestamp = normalized_headers.get("x-agent-timestamp")
    nonce = normalized_headers.get("x-agent-nonce")
    signature = normalized_headers.get("x-agent-signature")

    if config.require_signature_input_header:
        signature_input = normalized_headers.get("x-agent-signature-input")
        if signature_input != SIGNATURE_INPUT:
            return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Invalid x-agent-signature-input")

    if not agent_id or not kid or not timestamp or not nonce or not signature:
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Missing required signature headers")

    try:
        parse_agent_id(agent_id)
    except Exception:
        return _failure(VerificationErrorCode.INVALID_AGENT_ID, "Invalid sender agent_id")

    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Reference time must include a timezone")
    current = current.astimezone(UTC)
    try:
        request_time = parse_rfc3339_utc_seconds(timestamp)
    except (TypeError, ValueError):
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Invalid request timestamp")

    if abs((current - request_time).total_seconds()) > profile.clock_skew_seconds:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Request timestamp is outside allowed skew")

    try:
        resolved = await resolve_agent(
            agent_id,
            profile=profile,
            http_client=http_client,
            cache=cache,
            config=resolver_config,
        )
    except Exception:
        return _failure(VerificationErrorCode.METADATA_FETCH_FAILED, "Unable to resolve sender metadata")

    try:
        key = select_verification_key(resolved.metadata, kid=kid, now=current)
    except Exception as exc:
        reason = str(exc)
        if "revoked" in reason:
            return _failure(VerificationErrorCode.KEY_REVOKED, "Signing key is revoked")
        if "expired" in reason:
            return _failure(VerificationErrorCode.KEY_EXPIRED, "Signing key is expired")
        return _failure(VerificationErrorCode.KEY_NOT_FOUND, "Signing key is unavailable")

    try:
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
    except (TypeError, ValueError):
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Request body is not canonical JSON")
    try:
        verified = verify_signature(
            public_key_pem=key.public_key_pem,
            public_key_base64url=key.public_key_base64url,
            data=canonical.encode("utf-8"),
            signature_base64url=signature,
            alg=key.alg,
        )
    except Exception:
        return _failure(VerificationErrorCode.INVALID_METADATA, "Verification key material is invalid")
    if not verified:
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Signature verification failed")

    nonce_key = f"http:{agent_id}:{nonce}"
    if not await nonce_store.consume(nonce_key, profile.nonce_ttl_seconds):
        return _failure(VerificationErrorCode.NONCE_REPLAYED, "Nonce has already been used")
    return VerificationSuccess(
        agent_id=agent_id,
        kid=kid,
        metadata=resolved.metadata,
        canonical=canonical,
        request_id=request_id,
    )


def verify_http_request_sync(**kwargs: Any) -> VerificationSuccess | VerificationFailure:
    return asyncio.run(verify_http_request(**kwargs))
