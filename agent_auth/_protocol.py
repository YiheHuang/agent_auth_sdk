"""SignedEnvelope v1：所有本地、远程和 Registry 写操作共用。"""

from __future__ import annotations

import base64
import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ._errors import AgentAuthError
from ._state import NonceState
from ._types import AgentRecord, AuthContext

_RFC3339_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class Signer(Protocol):
    @property
    def kid(self) -> str: ...

    @property
    def public_key(self) -> str: ...

    async def sign(self, data: bytes) -> bytes: ...


@dataclass(slots=True, frozen=True)
class SignedEnvelope:
    v: int
    id: str
    sender: str
    audience: str
    kid: str
    issued_at: str
    type: str
    reply_to: str | None
    payload: str
    signature: str

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "v": self.v,
            "id": self.id,
            "sender": self.sender,
            "audience": self.audience,
            "kid": self.kid,
            "issued_at": self.issued_at,
            "type": self.type,
            "reply_to": self.reply_to,
            "payload": self.payload,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> SignedEnvelope:
        expected = {"v", "id", "sender", "audience", "kid", "issued_at", "type", "reply_to", "payload", "signature"}
        if set(value) != expected:
            raise AgentAuthError("ENVELOPE_INVALID", "Signed envelope fields are invalid")
        try:
            raw_version = value["v"]
            if type(raw_version) is not int:
                raise TypeError
            text_fields = ("id", "sender", "audience", "kid", "issued_at", "type", "payload", "signature")
            if any(not isinstance(value[field], str) for field in text_fields):
                raise TypeError
            if value["reply_to"] is not None and not isinstance(value["reply_to"], str):
                raise TypeError
            envelope = cls(
                v=raw_version,
                id=cast(str, value["id"]),
                sender=cast(str, value["sender"]),
                audience=cast(str, value["audience"]),
                kid=cast(str, value["kid"]),
                issued_at=cast(str, value["issued_at"]),
                type=cast(str, value["type"]),
                reply_to=cast(str | None, value["reply_to"]),
                payload=cast(str, value["payload"]),
                signature=cast(str, value["signature"]),
            )
        except (TypeError, ValueError) as exc:
            raise AgentAuthError("ENVELOPE_INVALID", "Signed envelope fields are invalid") from exc
        if envelope.v != 1 or not all(
            (
                envelope.id,
                envelope.sender,
                envelope.audience,
                envelope.kid,
                envelope.issued_at,
                envelope.type,
                envelope.payload,
            )
        ):
            raise AgentAuthError("ENVELOPE_INVALID", "Signed envelope fields are invalid")
        return envelope


class DevSigner:
    """仅供 dev 模式使用的进程内 P-256 signer。"""

    def __init__(self, agent_id: str) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._kid = f"{agent_id}#dev:{uuid.uuid4().hex[:12]}"

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def public_key(self) -> str:
        der = self._private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b64url_encode(der)

    async def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))


async def sign_envelope(
    *,
    sender: str,
    audience: str,
    call_type: str,
    payload: Any,
    signer: Signer,
    reply_to: str | None = None,
    request_id: str | None = None,
    issued_at: datetime | None = None,
) -> SignedEnvelope:
    timestamp = issued_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
        raise AgentAuthError("TIMESTAMP_INVALID", "issued_at must use UTC")
    value = SignedEnvelope(
        v=1,
        id=request_id or str(uuid.uuid4()),
        sender=sender,
        audience=audience,
        kid=signer.kid,
        issued_at=timestamp.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        type=call_type,
        reply_to=reply_to,
        payload=b64url_encode(strict_json_bytes(payload)),
        signature="pending",
    )
    signature = await signer.sign(canonical_bytes(value.unsigned_dict()))
    return SignedEnvelope(**{**value.unsigned_dict(), "signature": b64url_encode(signature)})  # type: ignore[arg-type]


def verify_envelope(
    envelope: SignedEnvelope,
    *,
    record: AgentRecord,
    audience: str,
    nonce_state: NonceState | None,
    expected_type: str | None = None,
    expected_reply_to: str | None = None,
    now: datetime | None = None,
    allowed_skew_seconds: int = 120,
) -> tuple[AuthContext, Any]:
    current = now or datetime.now(UTC)
    if envelope.sender != record.agent_id or envelope.kid != record.kid:
        raise AgentAuthError(
            "SIGNER_MISMATCH",
            "Envelope signer does not match Registry metadata",
            request_id=envelope.id,
        )
    if envelope.audience != audience:
        raise AgentAuthError("AUDIENCE_MISMATCH", "Envelope audience does not match receiver", request_id=envelope.id)
    if expected_type is not None and envelope.type != expected_type:
        raise AgentAuthError("TYPE_MISMATCH", "Envelope type is not accepted", request_id=envelope.id)
    if expected_reply_to is not None and envelope.reply_to != expected_reply_to:
        raise AgentAuthError("REPLY_MISMATCH", "Envelope reply correlation is invalid", request_id=envelope.id)
    issued = parse_timestamp(envelope.issued_at)
    if abs((current - issued).total_seconds()) > allowed_skew_seconds:
        raise AgentAuthError(
            "TIMESTAMP_EXPIRED",
            "Envelope timestamp is outside the accepted window",
            request_id=envelope.id,
        )
    try:
        public_key = serialization.load_der_public_key(b64url_decode(record.public_key))
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError
        public_key.verify(
            b64url_decode(envelope.signature),
            canonical_bytes(envelope.unsigned_dict()),
            ec.ECDSA(hashes.SHA256()),
        )
    except (AgentAuthError, InvalidSignature, TypeError, ValueError) as exc:
        raise AgentAuthError("SIGNATURE_INVALID", "Envelope signature is invalid", request_id=envelope.id) from exc
    expires = issued + timedelta(seconds=allowed_skew_seconds)
    if nonce_state is not None and not nonce_state.consume(envelope.sender, envelope.id, expires):
        raise AgentAuthError("NONCE_REPLAYED", "Envelope has already been consumed", request_id=envelope.id)
    try:
        payload = json.loads(
            b64url_decode(envelope.payload),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (AgentAuthError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentAuthError("PAYLOAD_INVALID", "Envelope payload is not valid JSON", request_id=envelope.id) from exc
    return (
        AuthContext(
            sender=record.agent_id,
            kid=record.kid,
            capabilities=record.capabilities,
            request_id=envelope.id,
            call_type=envelope.type,
        ),
        payload,
    )


def strict_json_bytes(value: Any) -> bytes:
    _reject_non_finite(value)
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentAuthError("PAYLOAD_INVALID", "Payload must be JSON serializable") from exc


def canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def parse_timestamp(value: str) -> datetime:
    if not _RFC3339_SECONDS.fullmatch(value):
        raise AgentAuthError("TIMESTAMP_INVALID", "Timestamp must use UTC RFC 3339 second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AgentAuthError("TIMESTAMP_INVALID", "Timestamp is invalid") from exc


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    try:
        if "=" in value:
            raise ValueError
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError, TypeError) as exc:
        raise AgentAuthError("BASE64_INVALID", "Value is not valid base64url") from exc


def public_key_from_pem(value: str) -> str:
    try:
        key = serialization.load_pem_public_key(value.encode("utf-8"))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError
        return b64url_encode(
            key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
    except (TypeError, ValueError) as exc:
        raise AgentAuthError("PUBLIC_KEY_INVALID", "Public key must be P-256 SubjectPublicKeyInfo PEM") from exc


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise AgentAuthError("PAYLOAD_INVALID", "NaN and Infinity are not supported")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AgentAuthError("PAYLOAD_INVALID", "JSON object keys must be strings")
            _reject_non_finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite(item)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON object key")
        value[key] = item
    return value
