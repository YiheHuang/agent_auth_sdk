"""Agent 间规范消息的签名与验签。"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from .config import MetadataResolverConfig, TEST_PROFILE, VerificationConfig
from .crypto import Signer, verify_signature
from .errors import VerificationErrorCode
from .http_utils import _to_base64url, ensure_bytes, sha256_base64url, to_iso_z
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
        message_time = timestamp.astimezone(timezone.utc)
        timestamp_value = to_iso_z(message_time)
    elif isinstance(timestamp, str):
        timestamp_value = timestamp
        message_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    else:
        message_time = datetime.now(timezone.utc)
        timestamp_value = to_iso_z(message_time)

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
        alg=algorithm,
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
) -> VerificationSuccess | VerificationFailure:
    config = config or VerificationConfig(profile=TEST_PROFILE)
    profile = config.profile
    parsed_message = message if isinstance(message, SignedAgentMessage) else SignedAgentMessage.model_validate(message)

    try:
        parse_agent_id(parsed_message.agent_id)
    except Exception as exc:
        return _failure(VerificationErrorCode.INVALID_AGENT_ID, str(exc))

    current = now or datetime.now(timezone.utc)
    message_time = parsed_message.timestamp
    if message_time.tzinfo is None:
        message_time = message_time.replace(tzinfo=timezone.utc)
    if abs((current - message_time.astimezone(timezone.utc)).total_seconds()) > profile.clock_skew_seconds:
        return _failure(VerificationErrorCode.TIMESTAMP_EXPIRED, "Message timestamp is outside allowed skew")

    nonce_key = f"{parsed_message.agent_id}:{parsed_message.nonce}"
    if await nonce_store.has(nonce_key):
        return _failure(VerificationErrorCode.NONCE_REPLAYED, "Nonce has already been used")

    try:
        resolved = await resolve_agent(
            parsed_message.agent_id,
            profile=profile,
            http_client=http_client,
            cache=cache,
            config=resolver_config,
        )
    except Exception as exc:
        return _failure(VerificationErrorCode.METADATA_FETCH_FAILED, str(exc))

    try:
        key = select_verification_key(resolved.metadata, kid=parsed_message.kid, now=current)
    except Exception as exc:
        reason = str(exc)
        if "revoked" in reason:
            return _failure(VerificationErrorCode.KEY_REVOKED, reason)
        if "expired" in reason:
            return _failure(VerificationErrorCode.KEY_EXPIRED, reason)
        return _failure(VerificationErrorCode.KEY_NOT_FOUND, reason)

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
    verified = verify_signature(
        public_key_pem=key.public_key_pem,
        public_key_base64url=key.public_key_base64url,
        data=canonical.encode("utf-8"),
        signature_base64url=parsed_message.signature,
        alg=key.alg,
    )
    if not verified:
        return _failure(VerificationErrorCode.SIGNATURE_INVALID, "Signature verification failed")

    await nonce_store.set(nonce_key, profile.nonce_ttl_seconds)
    return VerificationSuccess(
        agent_id=parsed_message.agent_id,
        kid=parsed_message.kid,
        metadata=resolved.metadata,
        canonical=canonical,
        message=parsed_message,
    )


def sign_agent_message_sync(**kwargs: object) -> SignedAgentMessage:
    return asyncio.run(sign_agent_message(**kwargs))


def verify_agent_message_sync(**kwargs: object) -> VerificationSuccess | VerificationFailure:
    return asyncio.run(verify_agent_message(**kwargs))
