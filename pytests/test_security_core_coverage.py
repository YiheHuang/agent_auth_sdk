from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agent_auth_sdk.config import TEST_PROFILE, MetadataResolverConfig, VerificationConfig
from agent_auth_sdk.crypto import public_key_to_base64url
from agent_auth_sdk.errors import MetadataValidationError
from agent_auth_sdk.messaging import sign_agent_message, verify_agent_message
from agent_auth_sdk.models import AgentKey, ResolveResult, SignedAgentMessage
from agent_auth_sdk.publish import render_agent_metadata
from agent_auth_sdk.registry_security import (
    agent_key_fingerprint,
    hash_api_key,
    public_key_fingerprint,
    sign_registry_add_key_proof,
    sign_registry_new_key_proof,
    sign_registry_publish_request,
    verify_api_key,
    verify_registry_add_key_proof,
    verify_registry_new_key_proof,
    verify_registry_publish_signature,
)
from agent_auth_sdk.signing import SIGNATURE_INPUT, sign_http_request
from agent_auth_sdk.stores import (
    FileMetadataCache,
    InMemoryMetadataCache,
    InMemoryNonceStore,
    RedisNonceStore,
)
from agent_auth_sdk.verification import verify_http_request


class _Signer:
    def __init__(self, *, algorithm: str = "ES256") -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self._algorithm = algorithm

    async def kid(self) -> str:
        return "key-1"

    async def algorithm(self) -> str:
        return self._algorithm

    async def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def public_pem(self) -> str:
        return (
            self.private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str, **kwargs: Any) -> bool:
        if kwargs.get("nx") and key in self.values:
            return False
        self.values[key] = value
        return True

    async def exists(self, key: str) -> int:
        return int(key in self.values)


def _metadata(signer: _Signer, *, key_status: str = "active"):
    return render_agent_metadata(
        agent_id="agent://sender.example/sender",
        domain="sender.example",
        name="sender",
        organization="Demo",
        endpoint="https://sender.example/invoke",
        capabilities=["send"],
        keys=[AgentKey(kid="key-1", public_key_pem=signer.public_pem(), status=key_status)],
    )


def _resolved(signer: _Signer) -> ResolveResult:
    return ResolveResult(metadata=_metadata(signer), resolved_at=datetime.now(UTC), etag='"v1"')


@pytest.mark.anyio
async def test_nonce_and_metadata_store_boundaries(tmp_path) -> None:
    nonce_store = InMemoryNonceStore()
    with pytest.raises(ValueError, match="positive"):
        await nonce_store.consume("invalid", 0)
    assert await nonce_store.consume("one", 30)
    assert not await nonce_store.consume("one", 30)
    assert await nonce_store.has("one")
    nonce_store._entries["expired"] = datetime.now(UTC) - timedelta(seconds=1)
    assert not await nonce_store.has("expired")
    await nonce_store.set("compat", 30)
    assert await nonce_store.has("compat")

    fake_redis = _FakeRedis()
    redis_store = RedisNonceStore(fake_redis, prefix="test:")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive"):
        await redis_store.consume("invalid", 0)
    assert await redis_store.consume("one", 30)
    assert not await redis_store.consume("one", 30)
    assert await redis_store.has("one")
    await redis_store.set("two", 30)
    assert await redis_store.has("two")

    signer = _Signer()
    result = _resolved(signer)
    memory_cache = InMemoryMetadataCache()
    assert await memory_cache.get(result.metadata.agent_id) is None
    await memory_cache.set(result.metadata.agent_id, result, 30)
    assert await memory_cache.get(result.metadata.agent_id) == result
    memory_cache._entries[result.metadata.agent_id] = (result, datetime.now(UTC) - timedelta(seconds=1))
    assert await memory_cache.get(result.metadata.agent_id) is None

    file_cache = FileMetadataCache(tmp_path / "cache.sqlite3")
    assert await file_cache.get(result.metadata.agent_id) is None
    await file_cache.set(result.metadata.agent_id, result, 30)
    cached = await file_cache.get(result.metadata.agent_id)
    assert cached is not None and cached.etag == '"v1"'
    updated = ResolveResult(metadata=result.metadata, resolved_at=datetime.now(UTC), etag='"v2"')
    await file_cache.set(result.metadata.agent_id, updated, 30)
    cached = await file_cache.get(result.metadata.agent_id)
    assert cached is not None and cached.etag == '"v2"'
    await file_cache.set(result.metadata.agent_id, updated, -1)
    assert await file_cache.get(result.metadata.agent_id) is None


@pytest.mark.anyio
async def test_message_verification_failure_matrix(monkeypatch) -> None:
    signer = _Signer()
    now = datetime.now(UTC).replace(microsecond=0)
    message = await sign_agent_message(
        agent_id="agent://sender.example/sender",
        signer=signer,
        payload={"ok": True},
        recipient="agent://receiver.example/receiver",
        timestamp=now,
        nonce="message-nonce",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500)))

    async def resolved(*args: Any, **kwargs: Any) -> ResolveResult:
        return _resolved(signer)

    monkeypatch.setattr("agent_auth_sdk.messaging.resolve_agent", resolved)
    success = await verify_agent_message(
        message=message,
        expected_recipient="agent://receiver.example/receiver",
        nonce_store=InMemoryNonceStore(),
        http_client=client,
        now=now,
    )
    assert success.ok

    replay_store = InMemoryNonceStore()
    assert (
        await verify_agent_message(
            message=message,
            expected_recipient=message.recipient,
            nonce_store=replay_store,
            http_client=client,
            now=now,
        )
    ).ok
    replay = await verify_agent_message(
        message=message,
        expected_recipient=message.recipient,
        nonce_store=replay_store,
        http_client=client,
        now=now,
    )
    assert replay.code == "NONCE_REPLAYED"

    non_z_timestamp = message.model_dump(mode="json")
    non_z_timestamp["timestamp"] = now.isoformat()
    fractional_timestamp = message.model_dump(mode="json")
    fractional_timestamp["timestamp"] = now.isoformat().replace("+00:00", ".123Z")
    cases: list[tuple[SignedAgentMessage | dict[str, Any], str | None, datetime, str]] = [
        ({"bad": "message"}, None, now, "MESSAGE_INVALID"),
        (non_z_timestamp, None, now, "MESSAGE_INVALID"),
        (fractional_timestamp, None, now, "MESSAGE_INVALID"),
        (message.model_copy(update={"agent_id": "invalid"}), None, now, "INVALID_AGENT_ID"),
        (message, "invalid", now, "INVALID_AGENT_ID"),
        (message, "agent://receiver.example/other", now, "RECIPIENT_MISMATCH"),
        (message, message.recipient, now.replace(tzinfo=None), "TIMESTAMP_EXPIRED"),
        (message, message.recipient, now + timedelta(hours=1), "TIMESTAMP_EXPIRED"),
    ]
    for candidate, recipient, reference, code in cases:
        failure = await verify_agent_message(
            message=candidate,
            expected_recipient=recipient,
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            now=reference,
        )
        assert failure.code == code

    async def broken_resolver(*args: Any, **kwargs: Any) -> ResolveResult:
        raise MetadataValidationError("offline")

    monkeypatch.setattr("agent_auth_sdk.messaging.resolve_agent", broken_resolver)
    failure = await verify_agent_message(
        message=message,
        nonce_store=InMemoryNonceStore(),
        http_client=client,
        now=now,
    )
    assert failure.code == "METADATA_FETCH_FAILED"

    monkeypatch.setattr("agent_auth_sdk.messaging.resolve_agent", resolved)
    for reason, code in [
        ("revoked key", "KEY_REVOKED"),
        ("expired key", "KEY_EXPIRED"),
        ("missing key", "KEY_NOT_FOUND"),
    ]:

        def bad_key(*args: Any, _reason: str = reason, **kwargs: Any) -> AgentKey:
            raise MetadataValidationError(_reason)

        monkeypatch.setattr("agent_auth_sdk.messaging.select_verification_key", bad_key)
        failure = await verify_agent_message(
            message=message,
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            now=now,
        )
        assert failure.code == code

    monkeypatch.setattr(
        "agent_auth_sdk.messaging.select_verification_key",
        lambda *args, **kwargs: _metadata(signer).keys[0],
    )
    invalid_payload = await verify_agent_message(
        message=message.model_copy(update={"payload": float("nan")}),
        nonce_store=InMemoryNonceStore(),
        http_client=client,
        now=now,
    )
    assert invalid_payload.code == "MESSAGE_INVALID"
    monkeypatch.setattr("agent_auth_sdk.messaging.verify_signature", lambda **kwargs: False)
    invalid = await verify_agent_message(
        message=message,
        nonce_store=InMemoryNonceStore(),
        http_client=client,
        now=now,
    )
    assert invalid.code == "SIGNATURE_INVALID"

    def broken_signature(**kwargs: Any) -> bool:
        raise ValueError("invalid key")

    monkeypatch.setattr("agent_auth_sdk.messaging.verify_signature", broken_signature)
    invalid_metadata = await verify_agent_message(
        message=message,
        nonce_store=InMemoryNonceStore(),
        http_client=client,
        now=now,
    )
    assert invalid_metadata.code == "INVALID_METADATA"
    await client.aclose()


@pytest.mark.anyio
async def test_sign_message_rejects_algorithm_and_accepts_string_timestamp() -> None:
    with pytest.raises(ValueError, match="ES256"):
        await sign_agent_message(
            agent_id="agent://sender.example/sender",
            signer=_Signer(algorithm="RS256"),
            payload={},
        )
    signed = await sign_agent_message(
        agent_id="agent://sender.example/sender",
        signer=_Signer(),
        payload={},
        timestamp="2026-01-02T03:04:05Z",
    )
    assert signed.timestamp == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    with pytest.raises(ValueError):
        await sign_agent_message(
            agent_id="agent://sender.example/sender",
            signer=_Signer(),
            payload={},
            recipient="invalid",
        )
    with pytest.raises(ValueError, match="second precision"):
        await sign_agent_message(
            agent_id="agent://sender.example/sender",
            signer=_Signer(),
            payload={},
            timestamp=datetime.now(UTC).replace(microsecond=1),
        )


@pytest.mark.anyio
async def test_http_verification_failure_matrix(monkeypatch) -> None:
    signer = _Signer()
    now = datetime.now(UTC).replace(microsecond=0)
    signed = await sign_http_request(
        method="POST",
        url="https://receiver.example/invoke",
        body={"ok": True},
        agent_id="agent://sender.example/sender",
        signer=signer,
        timestamp=now.isoformat().replace("+00:00", "Z"),
        nonce="http-nonce",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500)))

    async def resolved(*args: Any, **kwargs: Any) -> ResolveResult:
        return _resolved(signer)

    monkeypatch.setattr("agent_auth_sdk.verification.resolve_agent", resolved)
    base = dict(signed.headers)
    base["x-agent-signature-input"] = SIGNATURE_INPUT

    async def verify(headers: dict[str, str], reference: datetime = now, body: Any = None):
        return await verify_http_request(
            method="POST",
            url="https://receiver.example/invoke",
            headers=headers,
            body={"ok": True} if body is None else body,
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            config=VerificationConfig(profile=TEST_PROFILE),
            resolver_config=MetadataResolverConfig(profile=TEST_PROFILE),
            now=reference,
        )

    assert (await verify(base)).ok
    altered = dict(base)
    altered["x-agent-signature-input"] = "wrong"
    assert (await verify(altered)).code == "SIGNATURE_INVALID"
    missing = dict(base)
    missing.pop("x-agent-kid")
    assert (await verify(missing)).code == "SIGNATURE_INVALID"
    invalid_agent = dict(base)
    invalid_agent["x-agent-id"] = "invalid"
    assert (await verify(invalid_agent)).code == "INVALID_AGENT_ID"
    invalid_time = dict(base)
    invalid_time["x-agent-timestamp"] = "2026-01-01T00:00:00+00:00"
    assert (await verify(invalid_time)).code == "TIMESTAMP_EXPIRED"
    assert (await verify(base, now.replace(tzinfo=None))).code == "TIMESTAMP_EXPIRED"
    assert (await verify(base, now + timedelta(hours=1))).code == "TIMESTAMP_EXPIRED"

    async def broken_resolver(*args: Any, **kwargs: Any) -> ResolveResult:
        raise MetadataValidationError("offline")

    monkeypatch.setattr("agent_auth_sdk.verification.resolve_agent", broken_resolver)
    assert (await verify(base)).code == "METADATA_FETCH_FAILED"
    monkeypatch.setattr("agent_auth_sdk.verification.resolve_agent", resolved)

    for reason, code in [
        ("revoked key", "KEY_REVOKED"),
        ("expired key", "KEY_EXPIRED"),
        ("missing key", "KEY_NOT_FOUND"),
    ]:

        def bad_key(*args: Any, _reason: str = reason, **kwargs: Any) -> AgentKey:
            raise MetadataValidationError(_reason)

        monkeypatch.setattr("agent_auth_sdk.verification.select_verification_key", bad_key)
        assert (await verify(base)).code == code

    monkeypatch.setattr(
        "agent_auth_sdk.verification.select_verification_key",
        lambda *args, **kwargs: _metadata(signer).keys[0],
    )
    assert (await verify(base, body={"value": float("nan")})).code == "SIGNATURE_INVALID"
    monkeypatch.setattr("agent_auth_sdk.verification.verify_signature", lambda **kwargs: False)
    assert (await verify(base)).code == "SIGNATURE_INVALID"

    def broken_signature(**kwargs: Any) -> bool:
        raise ValueError("invalid key")

    monkeypatch.setattr("agent_auth_sdk.verification.verify_signature", broken_signature)
    assert (await verify(base)).code == "INVALID_METADATA"
    await client.aclose()


@pytest.mark.anyio
async def test_registry_security_tamper_and_invalid_configuration_matrix() -> None:
    signer = _Signer()
    public_key = AgentKey(kid="key-1", public_key_pem=signer.public_pem())
    timestamp = "2026-01-02T03:04:05Z"
    assert public_key_fingerprint(signer.public_pem()) == agent_key_fingerprint(public_key)
    encoded_key = AgentKey(
        kid="encoded",
        public_key_base64url=public_key_to_base64url(signer.public_pem()),
    )
    assert agent_key_fingerprint(encoded_key) == agent_key_fingerprint(public_key)
    with pytest.raises(ValueError, match="material"):
        agent_key_fingerprint(AgentKey.model_construct(kid="missing"))

    stored = hash_api_key("secret")
    assert verify_api_key("secret", stored)
    assert not verify_api_key("secret", "wrong$100000$salt$digest")
    assert not verify_api_key("secret", "pbkdf2_sha256$99999$salt$digest")
    assert not verify_api_key("secret", "pbkdf2_sha256$invalid$salt$digest")

    publish = await sign_registry_publish_request(
        path="/v1/agents/publish",
        host="registry.example",
        body={"agent_id": "agent://sender.example/sender"},
        agent_id="agent://sender.example/sender",
        client_id="developer",
        signer=signer,
        timestamp=timestamp,
        nonce="publish-nonce",
    )
    assert verify_registry_publish_signature(
        path="/v1/agents/publish",
        host="registry.example",
        body={"agent_id": "agent://sender.example/sender"},
        headers=publish.headers,
        public_key=public_key,
    )
    for key, value in [
        ("x-agent-signature-input", "wrong"),
        ("x-agent-signature", ""),
    ]:
        tampered = {**publish.headers, key: value}
        assert not verify_registry_publish_signature(
            path="/v1/agents/publish",
            host="registry.example",
            body={"agent_id": "agent://sender.example/sender"},
            headers=tampered,
            public_key=public_key,
        )
    with pytest.raises(ValueError, match="ES256"):
        await sign_registry_publish_request(
            path="/v1/agents/publish",
            host="registry.example",
            body={},
            agent_id="agent://sender.example/sender",
            client_id="developer",
            signer=_Signer(algorithm="RS256"),
        )

    new_proof = await sign_registry_new_key_proof(
        agent_id="agent://sender.example/sender",
        new_key=public_key,
        client_id="developer",
        host="registry.example",
        signer=signer,
        timestamp=timestamp,
        nonce="new-proof",
    )
    assert verify_registry_new_key_proof(
        agent_id="agent://sender.example/sender",
        new_key=public_key,
        headers=new_proof.headers,
        host="registry.example",
    )
    for key, value in [
        ("x-agent-signature-input", "wrong"),
        ("x-agent-id", "agent://sender.example/other"),
        ("x-agent-signature", ""),
    ]:
        assert not verify_registry_new_key_proof(
            agent_id="agent://sender.example/sender",
            new_key=public_key,
            headers={**new_proof.headers, key: value},
            host="registry.example",
        )
    mismatched = public_key.model_copy(update={"kid": "other"})
    with pytest.raises(ValueError, match="match"):
        await sign_registry_new_key_proof(
            agent_id="agent://sender.example/sender",
            new_key=mismatched,
            client_id="developer",
            host="registry.example",
            signer=signer,
        )
    with pytest.raises(ValueError, match="ES256"):
        await sign_registry_new_key_proof(
            agent_id="agent://sender.example/sender",
            new_key=public_key,
            client_id="developer",
            host="registry.example",
            signer=_Signer(algorithm="RS256"),
        )

    add_proof = await sign_registry_add_key_proof(
        agent_id="agent://sender.example/sender",
        new_key=public_key,
        client_id="developer",
        host="registry.example",
        signer=signer,
        timestamp=timestamp,
        nonce="add-proof",
    )
    assert verify_registry_add_key_proof(
        agent_id="agent://sender.example/sender",
        new_key=public_key,
        headers=add_proof.headers,
        host="registry.example",
    )
    for key, value in [
        ("x-agent-signature-input", "wrong"),
        ("x-agent-id", "agent://sender.example/other"),
        ("x-agent-signature", ""),
    ]:
        assert not verify_registry_add_key_proof(
            agent_id="agent://sender.example/sender",
            new_key=public_key,
            headers={**add_proof.headers, key: value},
            host="registry.example",
        )
    with pytest.raises(ValueError, match="match"):
        await sign_registry_add_key_proof(
            agent_id="agent://sender.example/sender",
            new_key=mismatched,
            client_id="developer",
            host="registry.example",
            signer=signer,
        )
    with pytest.raises(ValueError, match="ES256"):
        await sign_registry_add_key_proof(
            agent_id="agent://sender.example/sender",
            new_key=public_key,
            client_id="developer",
            host="registry.example",
            signer=_Signer(algorithm="RS256"),
        )
