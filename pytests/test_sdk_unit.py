from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import UTC, datetime

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agent_auth_sdk import AgentInstance, AgentVerifier, InMemoryNonceStore
from agent_auth_sdk.config import STRICT_PROFILE, TEST_PROFILE
from agent_auth_sdk.crypto import CallableSigner, verify_signature
from agent_auth_sdk.errors import MetadataValidationError
from agent_auth_sdk.http_utils import build_canonical_request
from agent_auth_sdk.identity import assert_strict_agent_id, build_agent_id, parse_agent_id
from agent_auth_sdk.metadata import select_verification_key
from agent_auth_sdk.models import AgentKey, AgentRegistryDocument, VerificationSuccess
from agent_auth_sdk.observability import AgentAuthEvent, emit_event
from agent_auth_sdk.publish import render_agent_metadata
from agent_auth_sdk.registry_client import RegistryClient
from agent_auth_sdk.registry_security import hash_api_key, legacy_hash_api_key, verify_api_key
from agent_auth_sdk.signing import sign_http_request
from agent_auth_sdk.vault_kms import (
    VaultKmsConfig,
    VaultTransitPublicKeyResolver,
    VaultTransitSigner,
    parse_vault_signature,
    read_vault_token,
)


def _generate_es256_pem_pair() -> tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


class _TestEs256Signer:
    def __init__(self, private_pem: str, kid: str = "vault:test") -> None:
        self._private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        self._kid = kid

    async def kid(self) -> str:
        return self._kid

    async def algorithm(self) -> str:
        return "ES256"

    async def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))


class _FakeTransit:
    def __init__(self, public_pem: str, private_pem: str | None = None, *, sign_error: Exception | None = None) -> None:
        self._public_pem = public_pem
        self._private_key = (
            serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None) if private_pem else None
        )
        self._sign_error = sign_error
        self._created_keys: list[str] = []

    def read_key(self, name: str, mount_point: str = "transit"):
        return {
            "data": {
                "type": "ecdsa-p256",
                "latest_version": 1,
                "keys": {"1": {"public_key": self._public_pem}},
            }
        }

    def sign_data(self, **kwargs):
        if self._sign_error is not None:
            raise self._sign_error
        message = base64.b64decode(kwargs["hash_input"])
        signature = self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return {"data": {"signature": "vault:v1:" + base64.b64encode(signature).decode("ascii")}}

    def create_key(self, name: str, key_type: str = "ecdsa-p256", mount_point: str = "transit", **kwargs):
        self._created_keys.append(name)
        return {"data": {"name": name, "type": key_type}}


class _FakeVaultClient:
    def __init__(self, public_pem: str, private_pem: str | None = None, *, sign_error: Exception | None = None) -> None:
        self.secrets = type(
            "Secrets",
            (),
            {"transit": _FakeTransit(public_pem, private_pem, sign_error=sign_error)},
        )()


def test_parse_agent_id_supports_host_port_and_nested_path() -> None:
    parsed = parse_agent_id("agent://127.0.0.1:8010/company/weather/bot")
    assert parsed.host == "127.0.0.1:8010"
    assert parsed.agent_name == "bot"
    assert parsed.path_segments == ("company", "weather", "bot")


def test_build_agent_id() -> None:
    assert build_agent_id("localhost:9000", "assistant") == "agent://localhost:9000/assistant"


def test_strict_agent_id_rejects_ip_and_reserved_hosts() -> None:
    assert_strict_agent_id("agent://public.example/assistant")
    for agent_id in (
        "agent://127.0.0.1/assistant",
        "agent://[::1]/assistant",
        "agent://localhost/assistant",
        "agent://service.internal/assistant",
    ):
        with pytest.raises(ValueError, match="strict"):
            assert_strict_agent_id(agent_id)


def test_registry_client_requires_https_by_default() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        RegistryClient(base_url="http://registry.local", client_id="dev", api_key="secret")
    client = RegistryClient(
        base_url="http://registry.local",
        client_id="dev",
        api_key="secret",
        allow_insecure_http=True,
    )
    assert client.base_url == "http://registry.local"
    with pytest.raises(ValueError, match="userinfo"):
        RegistryClient(base_url="https://user@registry.example", client_id="dev", api_key="secret")
    with pytest.raises(ValueError, match="positive"):
        RegistryClient(base_url="https://registry.example", client_id="dev", api_key="secret", timeout_seconds=0)


def test_vault_kms_config_requires_required_fields() -> None:
    with pytest.raises(TypeError):
        VaultKmsConfig(
            vault_addr="http://127.0.0.1:8200",
            vault_token="root",
            transit_mount="transit",
        )


@pytest.mark.anyio
async def test_sign_and_verify_public_key_material_es256() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:test")
    signed = await sign_http_request(
        method="POST",
        url="http://127.0.0.1:8010/invoke",
        body={"hello": "world"},
        agent_id="agent://127.0.0.1:8010/gateway",
        signer=signer,
    )
    assert verify_signature(
        public_key_pem=public_pem,
        public_key_base64url=None,
        data=signed.canonical.encode("utf-8"),
        signature_base64url=signed.headers["x-agent-signature"],
        alg="ES256",
    )


@pytest.mark.anyio
async def test_sign_and_verify_public_key_material_es256_base64url() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:test")
    signed = await sign_http_request(
        method="POST",
        url="http://127.0.0.1:8010/invoke",
        body={"hello": "world"},
        agent_id="agent://127.0.0.1:8010/gateway",
        signer=signer,
    )
    assert verify_signature(
        public_key_pem=public_pem,
        public_key_base64url=None,
        data=signed.canonical.encode("utf-8"),
        signature_base64url=signed.headers["x-agent-signature"],
        alg="ES256",
    )


def test_canonical_request_stability() -> None:
    canonical, body_digest = build_canonical_request(
        method="POST",
        url="https://demo.example.com/invoke?x=1",
        body={"foo": "bar"},
        agent_id="agent://demo.example.com/weather",
        kid="main",
        timestamp="2026-06-11T00:00:00Z",
        nonce="nonce-1",
    )
    assert canonical.startswith("POST\n/invoke?x=1\n")
    assert len(body_digest) > 10


def test_select_verification_key_rejects_expired_key() -> None:
    _, public_pem = _generate_es256_pem_pair()
    metadata = render_agent_metadata(
        agent_id="agent://demo.example.com/weather",
        domain="demo.example.com",
        name="weather",
        organization="Demo Org",
        endpoint="https://demo.example.com/invoke",
        capabilities=[],
        keys=[
            AgentKey(
                kid="main",
                public_key_pem=public_pem,
                status="active",
                not_after=datetime(2020, 1, 1, tzinfo=UTC),
            )
        ],
    )
    with pytest.raises(MetadataValidationError):
        select_verification_key(metadata, kid="main", now=datetime(2026, 1, 1, tzinfo=UTC))


def test_profiles_have_expected_policy() -> None:
    assert TEST_PROFILE.allow_http is True
    assert STRICT_PROFILE.allow_http is False


@pytest.mark.anyio
async def test_nonce_store_detects_replay() -> None:
    store = InMemoryNonceStore()
    await store.set("a", 600)
    assert await store.has("a") is True


def test_agent_instance_from_signer_builds_metadata() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        signer=_TestEs256Signer(private_pem, kid="vault:test"),
        public_key_pem=public_pem,
        kid="vault:test",
        capabilities=["publish", "sign", "verify"],
        environment="prod",
        alg="ES256",
    )
    assert agent.agent_id == "agent://192.144.228.237/publisher"
    assert agent.metadata is not None
    assert agent.metadata.domain == "192.144.228.237"
    assert agent.metadata.keys[0].kid == "vault:test"
    assert agent.metadata.keys[0].alg == "ES256"


def test_export_well_known_merges_multiple_agents(tmp_path) -> None:
    agents = []
    for name in ("coordinator", "security"):
        private_pem, public_pem = _generate_es256_pem_pair()
        agents.append(
            AgentInstance.from_signer(
                domain="demo.example.com",
                name=name,
                organization="Demo",
                endpoint=f"https://demo.example.com/{name}",
                signer=_TestEs256Signer(private_pem, kid=f"key-{name}"),
                public_key_pem=public_pem,
                kid=f"key-{name}",
            )
        )

    for agent in agents:
        agent.export_metadata(tmp_path)

    payload = json.loads((tmp_path / ".well-known" / "agent.json").read_text(encoding="utf-8"))
    document = AgentRegistryDocument.model_validate(payload)
    assert [entry.agent_id for entry in document.agents] == [
        "agent://demo.example.com/coordinator",
        "agent://demo.example.com/security",
    ]


@pytest.mark.anyio
async def test_agent_instance_sign_message_accepts_nonce() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:test")
    agent = AgentInstance.from_signer(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        signer=signer,
        public_key_pem=public_pem,
        kid="vault:test",
    )
    message = await agent.sign_message(
        payload={"hello": "world"},
        recipient="agent://agent.example.com/coordinator",
        message_type="demo",
        nonce="fixed-nonce",
    )
    assert message.nonce == "fixed-nonce"


def test_vault_resolver_accepts_p256_key() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    resolver = VaultTransitPublicKeyResolver(
        VaultKmsConfig(
            vault_addr="http://127.0.0.1:8200",
            vault_token="root",
            transit_mount="transit",
            key_name="agent-key",
            allow_insecure_raw_token=True,
        ),
        client=_FakeVaultClient(public_pem, private_pem),
    )
    description = resolver.describe()
    assert description.key_type == "ecdsa-p256"
    assert description.hash_algorithm == "sha2-256"
    assert description.marshaling_algorithm == "asn1"


def test_vault_resolver_rejects_non_p256_key() -> None:
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    resolver = VaultTransitPublicKeyResolver(
        VaultKmsConfig(
            vault_addr="http://127.0.0.1:8200",
            vault_token="root",
            transit_mount="transit",
            key_name="agent-key",
            allow_insecure_raw_token=True,
        ),
        client=_FakeVaultClient(public_pem),
    )
    with pytest.raises(ValueError, match="ecdsa-p256"):
        resolver.describe()


def test_vault_signer_validate_access_rejects_when_signing_fails() -> None:
    _, public_pem = _generate_es256_pem_pair()
    signer = VaultTransitSigner(
        VaultKmsConfig(
            vault_addr="http://127.0.0.1:8200",
            vault_token="root",
            transit_mount="transit",
            key_name="agent-key",
            allow_insecure_raw_token=True,
        ),
        client=_FakeVaultClient(public_pem, sign_error=RuntimeError("sign denied")),
    )
    with pytest.raises(RuntimeError, match="sign denied"):
        signer.validate_access()


@pytest.mark.anyio
async def test_vault_signer_default_kid_and_signature_parse() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = VaultTransitSigner(
        VaultKmsConfig(
            vault_addr="http://127.0.0.1:8200",
            vault_token="root",
            transit_mount="transit",
            key_name="agent-key",
            allow_insecure_raw_token=True,
        ),
        client=_FakeVaultClient(public_pem, private_pem),
    )
    assert await signer.kid() == "vault:transit/agent-key"
    signature = await signer.sign(b"hello")
    assert isinstance(signature, bytes)
    encoded = "vault:v1:" + base64.b64encode(signature).decode("ascii")
    assert parse_vault_signature(encoded) == signature


def test_agent_instance_from_vault_builds_es256_metadata(monkeypatch) -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    fake_client = _FakeVaultClient(public_pem, private_pem)

    from agent_auth_sdk import agent as agent_module

    monkeypatch.setattr(agent_module, "_build_vault_client", lambda config: fake_client)
    agent = AgentInstance.from_vault(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        vault_addr="http://127.0.0.1:8200",
        vault_token="root",
        allow_insecure_raw_token=True,
        transit_mount="transit",
        key_name="publisher-key",
        capabilities=["publish"],
        environment="prod",
    )
    assert agent.metadata is not None
    assert agent.metadata.keys[0].kid == "vault:transit/publisher-key:v1"
    assert agent.metadata.keys[0].alg == "ES256"


def test_vault_config_rejects_raw_token_in_production() -> None:
    with pytest.raises(ValueError, match="Raw vault_token"):
        VaultKmsConfig(
            vault_addr="https://vault.example.com",
            vault_token="raw-token",
            transit_mount="transit",
            key_name="agent-key",
        )

    with pytest.raises(ValueError, match="HTTPS"):
        VaultKmsConfig(
            vault_addr="http://vault.example.com",
            vault_token_file="/run/secrets/vault-token",
            transit_mount="transit",
            key_name="agent-key",
        )


def test_vault_config_reads_token_file(tmp_path) -> None:
    token_file = tmp_path / "vault-token"
    token_file.write_text("token-from-agent\n", encoding="utf-8")
    token_file.chmod(0o600)
    config = VaultKmsConfig(
        vault_addr="https://vault.example.com",
        vault_token_file=token_file,
        transit_mount="transit",
        key_name="agent-key",
    )
    assert read_vault_token(config) == "token-from-agent"


def test_vault_config_rejects_empty_token_file(tmp_path) -> None:
    token_file = tmp_path / "vault-token"
    token_file.write_text("\n", encoding="utf-8")
    token_file.chmod(0o600)
    config = VaultKmsConfig(
        vault_addr="https://vault.example.com",
        vault_token_file=token_file,
        transit_mount="transit",
        key_name="agent-key",
    )
    with pytest.raises(ValueError, match="empty"):
        read_vault_token(config)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
def test_vault_config_rejects_broad_token_file_permissions(tmp_path) -> None:
    token_file = tmp_path / "vault-token"
    token_file.write_text("token-from-agent\n", encoding="utf-8")
    token_file.chmod(0o644)
    config = VaultKmsConfig(
        vault_addr="https://vault.example.com",
        vault_token_file=token_file,
        transit_mount="transit",
        key_name="agent-key",
    )
    with pytest.raises(ValueError, match="permissions are too broad"):
        read_vault_token(config)


def test_vault_config_rejects_skip_verify_in_production() -> None:
    with pytest.raises(ValueError, match="TLS verification"):
        VaultKmsConfig(
            vault_addr="https://vault.example.com",
            vault_token_file="/tmp/token",
            transit_mount="transit",
            key_name="agent-key",
            verify=False,
        )


def test_api_key_hash_uses_pbkdf2_and_verifies_legacy_hash() -> None:
    stored = hash_api_key("secret-api-key")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_api_key("secret-api-key", stored) is True
    assert verify_api_key("wrong", stored) is False
    assert verify_api_key("secret-api-key", legacy_hash_api_key("secret-api-key")) is True


def test_from_vault_auto_create_key_enabled(monkeypatch) -> None:
    """from_vault(auto_create_key=True) 在 key 不存在时自动创建。"""
    private_pem, public_pem = _generate_es256_pem_pair()
    fake_client = _FakeVaultClient(public_pem, private_pem)

    from agent_auth_sdk import agent as agent_module

    # 记录 _ensure_transit_key 是否被调用
    calls = []

    def _tracking_ensure(config, client=None):
        calls.append(config.key_name)
        fake_transit = fake_client.secrets.transit
        fake_transit.create_key(name=config.key_name, key_type="ecdsa-p256")

    monkeypatch.setattr(agent_module, "_ensure_transit_key", _tracking_ensure)
    monkeypatch.setattr(agent_module, "_build_vault_client", lambda config: fake_client)

    agent = AgentInstance.from_vault(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        vault_addr="http://127.0.0.1:8200",
        vault_token="root",
        allow_insecure_raw_token=True,
        transit_mount="transit",
        key_name="weather-agent",
        auto_create_key=True,
    )
    assert len(calls) == 1
    assert calls[0] == "weather-agent"
    assert agent.metadata is not None
    assert agent.metadata.keys[0].kid == "vault:transit/weather-agent:v1"


def test_from_vault_auto_create_key_default_off(monkeypatch) -> None:
    """auto_create_key 默认 False，key 必须已存在。"""
    private_pem, public_pem = _generate_es256_pem_pair()

    from agent_auth_sdk import agent as agent_module

    fake_client = _FakeVaultClient(public_pem, private_pem)
    monkeypatch.setattr(agent_module, "_build_vault_client", lambda config: fake_client)

    agent = AgentInstance.from_vault(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        vault_addr="http://127.0.0.1:8200",
        vault_token="root",
        allow_insecure_raw_token=True,
        transit_mount="transit",
        key_name="weather-agent",
    )
    assert agent.metadata is not None
    assert agent.key_name == "weather-agent"


def test_rotate_key_requires_mode_specification() -> None:
    """rotate_key() 在两种方式都未提供时抛出 ValueError。"""
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:transit/weather-agent")
    agent = AgentInstance.from_signer(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        signer=signer,
        public_key_pem=public_pem,
        kid="vault:transit/weather-agent",
    )

    with pytest.raises(ValueError, match="Either new_key_name"):
        asyncio.run(
            agent.rotate_key(
                registry_url="https://registry.example.com/registry/agents/rotate-key",
                client_id="developer-a",
                api_key="test-key",
            )
        )


# ── add_key / revoke_key 单元测试 ──────────────────────────────────────────


def test_agent_key_status_revoked() -> None:
    """AgentKey 接受 status="revoked"。"""
    _, public_pem = _generate_es256_pem_pair()
    key = AgentKey(
        kid="vault:test",
        alg="ES256",
        public_key_pem=public_pem,
        status="revoked",
    )
    assert key.status == "revoked"


def test_select_verification_key_rejects_revoked_status() -> None:
    """status="revoked" 的 key 被 select_verification_key 拒绝。"""
    _, public_pem = _generate_es256_pem_pair()
    metadata = render_agent_metadata(
        agent_id="agent://demo.example.com/weather",
        domain="demo.example.com",
        name="weather",
        organization="Demo Org",
        endpoint="https://demo.example.com/invoke",
        capabilities=[],
        keys=[
            AgentKey(
                kid="main",
                public_key_pem=public_pem,
                status="revoked",
            )
        ],
    )
    with pytest.raises(MetadataValidationError):
        select_verification_key(metadata, kid="main", now=datetime(2026, 1, 1, tzinfo=UTC))


def test_select_verification_key_rejects_revoked_kid() -> None:
    """kid 在 revoked_kids 列表中的 key 被拒绝（即使 status="active"）。"""
    _, public_pem = _generate_es256_pem_pair()
    metadata = render_agent_metadata(
        agent_id="agent://demo.example.com/weather",
        domain="demo.example.com",
        name="weather",
        organization="Demo Org",
        endpoint="https://demo.example.com/invoke",
        capabilities=[],
        keys=[
            AgentKey(
                kid="main",
                public_key_pem=public_pem,
                status="active",
            )
        ],
        revoked_kids=["main"],
    )
    with pytest.raises(Exception, match="revoked"):
        select_verification_key(metadata, kid="main", now=datetime(2026, 1, 1, tzinfo=UTC))


def test_add_key_requires_mode_specification() -> None:
    """add_key() 在两种方式都未提供时抛出 ValueError。"""
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:transit/weather-agent")
    agent = AgentInstance.from_signer(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        signer=signer,
        public_key_pem=public_pem,
        kid="vault:transit/weather-agent",
    )

    with pytest.raises(ValueError, match="Either new_key_name"):
        asyncio.run(
            agent.add_key(
                registry_url="https://registry.example.com/registry/agents/add-key",
                client_id="developer-a",
                api_key="test-key",
            )
        )


def test_revoke_key_raises_when_kid_not_found() -> None:
    """revoke_key() 在 kid 不存在时抛出 ValueError。"""
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:transit/weather-agent")
    agent = AgentInstance.from_signer(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        signer=signer,
        public_key_pem=public_pem,
        kid="vault:transit/weather-agent",
    )

    with pytest.raises(ValueError, match="Key not found"):
        asyncio.run(
            agent.revoke_key(
                registry_url="https://registry.example.com/registry/agents/revoke-key",
                client_id="developer-a",
                api_key="test-key",
                kid_to_revoke="nonexistent",
            )
        )


def test_revoke_key_raises_when_last_active_key() -> None:
    """revoke_key() 拒绝撤销唯一的 active key。"""
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:transit/weather-agent")
    agent = AgentInstance.from_signer(
        domain="agent.example.com",
        name="weather",
        organization="Example Lab",
        endpoint="https://agent.example.com/tasks",
        signer=signer,
        public_key_pem=public_pem,
        kid="vault:transit/weather-agent",
    )

    with pytest.raises(ValueError, match="Cannot revoke the current signing key"):
        asyncio.run(
            agent.revoke_key(
                registry_url="https://registry.example.com/registry/agents/revoke-key",
                client_id="developer-a",
                api_key="test-key",
                kid_to_revoke="vault:transit/weather-agent",
            )
        )


@pytest.mark.anyio
async def test_registry_client_lifecycle_methods_and_async_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="key-1")
    agent = AgentInstance.from_signer(
        domain="agents.example.com",
        name="caller",
        organization="Test",
        endpoint="https://agents.example.com/invoke",
        signer=signer,
        public_key_pem=public_pem,
        kid="key-1",
    )
    calls: list[dict] = []

    async def fake_operation(*args, **kwargs):
        calls.append(kwargs)
        return {"ok": True}

    for name in (
        "publish_to_registry",
        "rotate_key_in_registry",
        "add_key_in_registry",
        "revoke_key_in_registry",
        "revoke_agent_in_registry",
    ):
        monkeypatch.setattr(f"agent_auth_sdk.registry_client.{name}", fake_operation)

    async def credential() -> str:
        return "secret"

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    client = RegistryClient(
        base_url="https://registry.example.com/v1/agents/publish",
        client_id="developer",
        api_key=credential,
        http_client=http_client,
    )
    key = agent.metadata.keys[0]
    assert await client.publish(agent.metadata, signer=signer) == {"ok": True}
    assert await client.rotate_key(
        agent_id=agent.agent_id,
        new_key=key,
        current_signer=signer,
        new_signer=signer,
    ) == {"ok": True}
    assert await client.add_key(
        agent_id=agent.agent_id,
        new_key=key,
        current_signer=signer,
        new_signer=signer,
    ) == {"ok": True}
    assert await client.revoke_key(
        agent_id=agent.agent_id,
        kid_to_revoke="old-key",
        current_signer=signer,
    ) == {"ok": True}
    assert await client.revoke_agent(agent_id=agent.agent_id, current_signer=signer) == {"ok": True}
    assert all(call["api_key"] == "secret" for call in calls)
    await client.__aexit__()
    assert http_client.is_closed is False
    await http_client.aclose()


@pytest.mark.anyio
async def test_verifier_authorization_policy_paths() -> None:
    verifier = AgentVerifier()
    success = VerificationSuccess(agent_id="agent://agents.example.com/caller", kid="key-1")

    class Policy:
        def __init__(self, result: bool | Exception) -> None:
            self.result = result

        async def authorize(self, result: VerificationSuccess, *, capability: str | None = None) -> bool:
            if isinstance(self.result, Exception):
                raise self.result
            return self.result

    assert await verifier.authorize(success, policy=Policy(True), capability="review") is success
    assert (await verifier.authorize(success, policy=Policy(False))).code == "POLICY_REJECTED"
    assert (await verifier.authorize(success, policy=Policy(RuntimeError("failed")))).code == "POLICY_REJECTED"
    await verifier.__aenter__()
    assert verifier._http_client is not None
    await verifier.__aexit__()
    assert verifier._http_client is None


@pytest.mark.anyio
async def test_callable_signer_and_event_sinks() -> None:
    async def sign(data: bytes) -> bytes:
        return b"signed:" + data

    signer = CallableSigner(kid_value="key-1", sign_callable=sign)
    assert await signer.kid() == "key-1"
    assert await signer.algorithm() == "ES256"
    assert await signer.sign(b"data") == b"signed:data"

    event = AgentAuthEvent(
        operation="test",
        source_agent_id=None,
        target_agent_id=None,
        ok=True,
        duration_ms=1.0,
    )
    received: list[AgentAuthEvent] = []

    async def async_sink(value: AgentAuthEvent) -> None:
        received.append(value)

    await emit_event(None, event)
    await emit_event(received.append, event)
    await emit_event(async_sink, event)
    assert received == [event, event]
    assert event.as_dict()["operation"] == "test"
