from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_auth import AgentAuthError
from agent_auth._protocol import (
    DevSigner,
    SignedEnvelope,
    b64url_decode,
    canonical_bytes,
    parse_timestamp,
    public_key_from_pem,
    sign_envelope,
    strict_json_bytes,
    verify_envelope,
)
from agent_auth._state import MemoryNonceState, SQLiteNonceState
from agent_auth._types import AgentRecord


def _signed(*, issued_at: datetime | None = None, reply_to: str | None = None) -> tuple[SignedEnvelope, AgentRecord]:
    signer = DevSigner("agent://127.0.0.1/a")
    envelope = asyncio.run(
        sign_envelope(
            sender="agent://127.0.0.1/a",
            audience="agent://127.0.0.1/b",
            call_type="agent.call",
            payload={"text": "你好", "value": 1.5},
            signer=signer,
            issued_at=issued_at,
            reply_to=reply_to,
            request_id="request-1",
        )
    )
    record = AgentRecord(envelope.sender, "http://127.0.0.1/a", ("read",), signer.kid, signer.public_key, "now")
    return envelope, record


def test_envelope_sign_verify_and_canonical_shape() -> None:
    envelope, record = _signed()
    state = MemoryNonceState()
    context, payload = verify_envelope(
        envelope,
        record=record,
        audience="agent://127.0.0.1/b",
        nonce_state=state,
        expected_type="agent.call",
    )
    assert context.sender == record.agent_id
    assert context.capabilities == ("read",)
    assert payload == {"text": "你好", "value": 1.5}
    assert json.loads(canonical_bytes(envelope.unsigned_dict()))["reply_to"] is None
    assert json.loads(b64url_decode(envelope.payload)) == payload


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("audience", "agent://127.0.0.1/c", "AUDIENCE_MISMATCH"),
        ("type", "other", "TYPE_MISMATCH"),
        ("kid", "wrong", "SIGNER_MISMATCH"),
        ("signature", "bad", "SIGNATURE_INVALID"),
    ],
)
def test_envelope_rejects_tampering(field: str, value: str, code: str) -> None:
    envelope, record = _signed()
    changed = SignedEnvelope(**{**envelope.as_dict(), field: value})  # type: ignore[arg-type]
    with pytest.raises(AgentAuthError, match=code):
        verify_envelope(
            changed,
            record=record,
            audience="agent://127.0.0.1/b",
            nonce_state=MemoryNonceState(),
            expected_type="agent.call",
        )


def test_envelope_replay_reply_and_time_failures() -> None:
    envelope, record = _signed(reply_to="parent")
    state = MemoryNonceState()
    verify_envelope(
        envelope,
        record=record,
        audience=envelope.audience,
        nonce_state=state,
        expected_reply_to="parent",
    )
    with pytest.raises(AgentAuthError, match="NONCE_REPLAYED"):
        verify_envelope(envelope, record=record, audience=envelope.audience, nonce_state=state)
    with pytest.raises(AgentAuthError, match="REPLY_MISMATCH"):
        verify_envelope(
            envelope,
            record=record,
            audience=envelope.audience,
            nonce_state=MemoryNonceState(),
            expected_reply_to="other",
        )
    expired, expired_record = _signed(issued_at=datetime.now(UTC) - timedelta(minutes=10))
    with pytest.raises(AgentAuthError, match="TIMESTAMP_EXPIRED"):
        verify_envelope(
            expired,
            record=expired_record,
            audience=expired.audience,
            nonce_state=MemoryNonceState(),
        )


def test_strict_json_rejects_unsupported_values() -> None:
    assert strict_json_bytes({"a": 1}) == b'{"a":1}'
    with pytest.raises(AgentAuthError, match="PAYLOAD_INVALID"):
        strict_json_bytes({"value": float("nan")})
    with pytest.raises(AgentAuthError, match="PAYLOAD_INVALID"):
        strict_json_bytes({1: "bad"})
    with pytest.raises(AgentAuthError, match="PAYLOAD_INVALID"):
        strict_json_bytes(object())


def test_envelope_requires_exact_fields() -> None:
    envelope, _ = _signed()
    value = envelope.as_dict()
    value["extra"] = True
    with pytest.raises(AgentAuthError, match="ENVELOPE_INVALID"):
        SignedEnvelope.from_dict(value)
    for field, replacement in (("v", "1"), ("v", True), ("reply_to", 3), ("id", "")):
        value = envelope.as_dict()
        value[field] = replacement
        with pytest.raises(AgentAuthError, match="ENVELOPE_INVALID"):
            SignedEnvelope.from_dict(value)


def test_timestamp_base64_and_public_key_parsing_fail_closed() -> None:
    for value in ("2026-07-15T12:00:00+00:00", "2026-02-30T12:00:00Z"):
        with pytest.raises(AgentAuthError, match="TIMESTAMP_INVALID"):
            parse_timestamp(value)
    for value in ("bad=", "***"):
        with pytest.raises(AgentAuthError, match="BASE64_INVALID"):
            b64url_decode(value)
    with pytest.raises(AgentAuthError, match="PUBLIC_KEY_INVALID"):
        public_key_from_pem("not a key")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(AgentAuthError, match="PUBLIC_KEY_INVALID"):
        public_key_from_pem(pem)


def test_envelope_rejects_invalid_key_and_naive_sign_time() -> None:
    envelope, record = _signed()
    bad_record = AgentRecord(
        record.agent_id,
        record.endpoint,
        (),
        record.kid,
        "***",
        record.updated_at,
    )
    with pytest.raises(AgentAuthError, match="SIGNATURE_INVALID"):
        verify_envelope(envelope, record=bad_record, audience=envelope.audience, nonce_state=None)
    with pytest.raises(AgentAuthError, match="TIMESTAMP_INVALID"):
        asyncio.run(
            sign_envelope(
                sender=envelope.sender,
                audience=envelope.audience,
                call_type="agent.call",
                payload={},
                signer=DevSigner(envelope.sender),
                issued_at=datetime(2026, 7, 15),
            )
        )


def test_protocol_golden_vector() -> None:
    vector = json.loads(Path("docs/protocol-v1-vectors.json").read_text(encoding="utf-8"))
    envelope = SignedEnvelope.from_dict(vector["envelope"])
    assert canonical_bytes(envelope.unsigned_dict()).hex() == vector["canonical_unsigned_utf8_hex"]
    record = AgentRecord(
        envelope.sender,
        "https://sender.example/invoke",
        (),
        envelope.kid,
        vector["public_key_spki_der_base64url"],
        envelope.issued_at,
    )
    _, payload = verify_envelope(
        envelope,
        record=record,
        audience=envelope.audience,
        nonce_state=MemoryNonceState(),
        expected_type="agent.call",
        now=datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC),
    )
    assert payload == {"query": "hello", "limit": 3}


def test_sqlite_nonce_is_atomic_and_persistent(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    expiry = datetime.now(UTC) + timedelta(minutes=1)

    def consume() -> bool:
        return SQLiteNonceState(path).consume("sender", "same", expiry)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: consume(), range(8)))
    assert results.count(True) == 1
    assert SQLiteNonceState(path).consume("sender", "same", expiry) is False
