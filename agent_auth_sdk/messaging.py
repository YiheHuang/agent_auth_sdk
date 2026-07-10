"""Agent 间规范消息的签名与验签。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx

from .config import MetadataResolverConfig, VerificationConfig
from .crypto import Signer, verify_signature
from .errors import VerificationErrorCode
from .http_utils import _to_base64url, ensure_bytes, parse_rfc3339_utc_seconds, sha256_base64url, to_iso_z
from .identity import parse_agent_id
from .metadata import resolve_agent, select_verification_key
from .models import SignedAgentMessage, VerificationFailure, VerificationSuccess
from .stores import MetadataCache, NonceStore


def build_canonical_message(
    *,
    agent_id: str,
    kid: str,
    timestamp: str,
    nonce: str,
    payload: bytes | str | dict | list | None,
    payload_type: str,
    recipient: str | None = None,
    message_type: str | None = None,
) -> tuple[str, str]:
    """构造签名消息的稳定原文。"""

    payload_digest = sha256_base64url(ensure_bytes(payload))
    canonical_parts = [
        "agent-message-v1",
        f"agent_id:{agent_id}",
        f"kid:{kid}",
        f"timestamp:{timestamp}",
        f"nonce:{nonce}",
        f"payload_type:{payload_type}",
        f"payload_digest:{payload_digest}",
        f"recipient:{recipient or ''}",
        f"message_type:{message_type or ''}",
    ]
    return "\n".join(canonical_parts), payload_digest


def _failure(code: VerificationErrorCode, reason: str) -> VerificationFailure:
    return VerificationFailure(code=code.value, reason=reason)


async def sign_agent_message(
    *,
    agent_id: str,
    signer: Signer,
    payload: bytes | str | dict | list | None,
    payload_type: str = "application/json",
    recipient: str | None = None,
    message_type: str | None = None,
    timestamp: datetime | str | None = None,
    nonce: str | None = None,
) -> SignedAgentMessage:
    parse_agent_id(agent_id)
    kid = await signer.kid()
    algorithm = await signer.algorithm()
    if algorithm != "ES256":
        raise ValueError("Only ES256 is supported in beta-v1")

    if isinstance(timestamp, datetime):
        if timestamp.utcoffset() != timedelta(0) or timestamp.microsecond != 0:
            raise ValueError("timestamp must use UTC second precision")
        timestamp_value = to_iso_z(timestamp)
        message_time = parse_rfc3339_utc_seconds(timestamp_value)
    elif isinstance(timestamp, str):
        message_time = parse_rfc3339_utc_seconds(timestamp)
        timestamp_value = timestamp
    else:
        timestamp_value = to_iso_z(datetime.now(UTC))
        message_time = parse_rfc3339_utc_seconds(timestamp_value)

    if recipient is not None:
        parse_agent_id(recipient)

    message_nonce = nonce or str(uuid4())
    canonical, _ = build_canonical_message(
        agent_id=agent_id,
        kid=kid,
        timestamp=timestamp_value,
        nonce=message_nonce,
        payload=payload,
        payload_type=payload_type,
        recipient=recipient,
        message_type=message_type,
    )
    signature = await signer.sign(canonical.encode("utf-8"))
    return SignedAgentMessage(
        agent_id=agent_id,
        kid=kid,
        alg="ES256",
        timestamp=message_time,
        nonce=message_nonce,
        payload_type=payload_type,
        payload=payload,
        recipient=recipient,
        message_type=message_type,
        signature=_to_base64url(signature),
    )


async def verify_agent_message(
    *,
    message: SignedAgentMessage | dict,
    nonce_store: NonceStore,
    http_client: httpx.AsyncClient,
    cache: MetadataCache | None = None,
    config: VerificationConfig | None = None,
    resolver_config: MetadataResolverConfig | None = None,
    now: datetime | None = None,
    expected_recipient: str | None = None,
) -> VerificationSuccess | VerificationFailure:
    config = config or VerificationConfig()
    profile = config.profile
    if isinstance(message, dict):
        raw_timestamp = message.get("timestamp")
        if not isinstance(raw_timestamp, str):
            return _failure(VerificationErrorCode.MESSAGE_INVALID, "timestamp must be an RFC3339 string")
        try:
            parse_rfc3339_utc_seconds(raw_timestamp)
        except (TypeError, ValueError):
            return _failure(VerificationErrorCode.MESSAGE_INVALID, "Invalid message timestamp")
    try:
        parsed_message = (
            message if isinstance(message, SignedAgentMessage) else SignedAgentMessage.model_validate(message)
        )
    except Exception:
        return _failure(VerificationErrorCode.MESSAGE_INVALID, "Malformed signed Agent message")

    try:
        parse_agent_id(parsed_message.agent_id)
    except Exception:
        return _failure(VerificationErrorCode.INVALID_AGENT_ID, "Invalid sender agent_id")

    if expected_recipient is not None:
        try:
            parse_agent_id(expected_recipient)
        except Exception:
            return _failure(VerificationErrorCode.INVALID_AGENT_ID, "Invalid expected recipient agent_id")
        if parsed_message.recipient != expected_recipient:
            return _failure(
                VerificationErrorCode.RECIPIENT_MISMATCH,
                "Signed message recipient does not match the expected recipient",
            )

    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Reference time must include a timezone")
    current = current.astimezone(UTC)
    message_time = parsed_message.timestamp
    if message_time.utcoffset() != timedelta(0) or message_time.microsecond != 0:
        return _failure(VerificationErrorCode.MESSAGE_INVALID, "Message timestamp must use UTC second precision")
    if abs((current - message_time.astimezone(UTC)).total_seconds()) > profile.clock_skew_seconds:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Message timestamp is outside allowed skew")

    try:
        resolved = await resolve_agent(
            parsed_message.agent_id,
            profile=profile,
            http_client=http_client,
            cache=cache,
            config=resolver_config,
        )
    except Exception:
        return _failure(VerificationErrorCode.METADATA_FETCH_FAILED, "Unable to resolve sender metadata")

    try:
        key = select_verification_key(resolved.metadata, kid=parsed_message.kid, now=current)
    except Exception as exc:
        reason = str(exc)
        if "revoked" in reason:
            return _failure(VerificationErrorCode.KEY_REVOKED, "Signing key is revoked")
        if "expired" in reason:
            return _failure(VerificationErrorCode.KEY_EXPIRED, "Signing key is expired")
        return _failure(VerificationErrorCode.KEY_NOT_FOUND, "Signing key is unavailable")

    try:
        canonical, _ = build_canonical_message(
            agent_id=parsed_message.agent_id,
            kid=parsed_message.kid,
            timestamp=to_iso_z(message_time),
            nonce=parsed_message.nonce,
            payload=parsed_message.payload,
            payload_type=parsed_message.payload_type,
            recipient=parsed_message.recipient,
            message_type=parsed_message.message_type,
        )
    except (TypeError, ValueError):
        return _failure(VerificationErrorCode.MESSAGE_INVALID, "Message payload is not canonical JSON")
    try:
        verified = verify_signature(
            public_key_pem=key.public_key_pem,
            public_key_base64url=key.public_key_base64url,
            data=canonical.encode("utf-8"),
            signature_base64url=parsed_message.signature,
            alg=key.alg,
        )
    except Exception:
        return _failure(VerificationErrorCode.INVALID_METADATA, "Verification key material is invalid")
    if not verified:
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Signature verification failed")

    nonce_key = f"message:{parsed_message.agent_id}:{parsed_message.nonce}"
    if not await nonce_store.consume(nonce_key, profile.nonce_ttl_seconds):
        return _failure(VerificationErrorCode.NONCE_REPLAYED, "Nonce has already been used")
    return VerificationSuccess(
        agent_id=parsed_message.agent_id,
        kid=parsed_message.kid,
        metadata=resolved.metadata,
        canonical=canonical,
        message=parsed_message,
    )


def sign_agent_message_sync(
    *,
    agent_id: str,
    signer: Signer,
    payload: bytes | str | dict | list | None,
    payload_type: str = "application/json",
    recipient: str | None = None,
    message_type: str | None = None,
    timestamp: datetime | str | None = None,
    nonce: str | None = None,
) -> SignedAgentMessage:
    return asyncio.run(
        sign_agent_message(
            agent_id=agent_id,
            signer=signer,
            payload=payload,
            payload_type=payload_type,
            recipient=recipient,
            message_type=message_type,
            timestamp=timestamp,
            nonce=nonce,
        )
    )


def verify_agent_message_sync(
    *,
    message: SignedAgentMessage | dict,
    nonce_store: NonceStore,
    http_client: httpx.AsyncClient,
    cache: MetadataCache | None = None,
    config: VerificationConfig | None = None,
    resolver_config: MetadataResolverConfig | None = None,
    now: datetime | None = None,
    expected_recipient: str | None = None,
) -> VerificationSuccess | VerificationFailure:
    return asyncio.run(
        verify_agent_message(
            message=message,
            nonce_store=nonce_store,
            http_client=http_client,
            cache=cache,
            config=config,
            resolver_config=resolver_config,
            now=now,
            expected_recipient=expected_recipient,
        )
    )
