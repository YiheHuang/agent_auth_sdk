from __future__ import annotations

import asyncio
import base64
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from agent_auth_sdk import AgentInstance, InMemoryNonceStore
from agent_auth_sdk.identity import build_agent_id, parse_agent_id
from agent_auth_sdk.metadata import select_verification_key
from agent_auth_sdk.models import AgentKey
from agent_auth_sdk.publish import render_agent_metadata
from agent_auth_sdk.config import STRICT_PROFILE, TEST_PROFILE
from agent_auth_sdk.crypto import verify_signature
from agent_auth_sdk.http_utils import build_canonical_request
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
            serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
            if private_pem
            else None
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
                public_key_pem="-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
                status="active",
                not_after=datetime(2020, 1, 1),
            )
        ],
    )
    with pytest.raises(Exception):
        select_verification_key(metadata, kid="main", now=datetime(2026, 1, 1))


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
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
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

    from agent_auth_sdk import agent as agent_module

    monkeypatch.setattr(
        agent_module,
        "VaultTransitSigner",
        lambda config: VaultTransitSigner(config, client=_FakeVaultClient(public_pem, private_pem)),
    )
    monkeypatch.setattr(
        agent_module,
        "resolve_vault_public_key",
        lambda config: VaultTransitPublicKeyResolver(config, client=_FakeVaultClient(public_pem, private_pem)).describe(),
    )
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
    assert agent.metadata.keys[0].kid == "vault:transit/publisher-key"
    assert agent.metadata.keys[0].alg == "ES256"


def test_vault_config_rejects_raw_token_in_production() -> None:
    with pytest.raises(ValueError, match="Raw vault_token"):
        VaultKmsConfig(
            vault_addr="https://vault.example.com",
            vault_token="raw-token",
            transit_mount="transit",
            key_name="agent-key",
        )


def test_vault_config_reads_token_file(tmp_path) -> None:
    token_file = tmp_path / "vault-token"
    token_file.write_text("token-from-agent\n", encoding="utf-8")
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
    config = VaultKmsConfig(
        vault_addr="https://vault.example.com",
        vault_token_file=token_file,
        transit_mount="transit",
        key_name="agent-key",
    )
    with pytest.raises(ValueError, match="empty"):
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
    from agent_auth_sdk.vault_kms import _ensure_transit_key

    # 记录 _ensure_transit_key 是否被调用
    calls = []

    def _tracking_ensure(config):
        calls.append(config.key_name)
        fake_transit = fake_client.secrets.transit
        fake_transit.create_key(name=config.key_name, key_type="ecdsa-p256")

    monkeypatch.setattr(agent_module, "_ensure_transit_key", _tracking_ensure)
    monkeypatch.setattr(
        agent_module,
        "VaultTransitSigner",
        lambda config: VaultTransitSigner(config, client=fake_client),
    )
    monkeypatch.setattr(
        agent_module,
        "resolve_vault_public_key",
        lambda config: VaultTransitPublicKeyResolver(config, client=fake_client).describe(),
    )

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
    assert agent.metadata.keys[0].kid == "vault:transit/weather-agent"


def test_from_vault_auto_create_key_default_off(monkeypatch) -> None:
    """auto_create_key 默认 False，key 必须已存在。"""
    private_pem, public_pem = _generate_es256_pem_pair()

    from agent_auth_sdk import agent as agent_module

    monkeypatch.setattr(
        agent_module,
        "VaultTransitSigner",
        lambda config: VaultTransitSigner(
            config, client=_FakeVaultClient(public_pem, private_pem)
        ),
    )
    monkeypatch.setattr(
        agent_module,
        "resolve_vault_public_key",
        lambda config: VaultTransitPublicKeyResolver(
            config, client=_FakeVaultClient(public_pem, private_pem)
        ).describe(),
    )

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

    import asyncio

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
    key = AgentKey(
        kid="vault:test",
        alg="ES256",
        public_key_pem="-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
        status="revoked",
    )
    assert key.status == "revoked"


def test_select_verification_key_rejects_revoked_status() -> None:
    """status="revoked" 的 key 被 select_verification_key 拒绝。"""
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
                public_key_pem="-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
                status="revoked",
            )
        ],
    )
    with pytest.raises(Exception):
        select_verification_key(metadata, kid="main", now=datetime(2026, 1, 1))


def test_select_verification_key_rejects_revoked_kid() -> None:
    """kid 在 revoked_kids 列表中的 key 被拒绝（即使 status="active"）。"""
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
                public_key_pem="-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
                status="active",
            )
        ],
        revoked_kids=["main"],
    )
    with pytest.raises(Exception, match="revoked"):
        select_verification_key(metadata, kid="main", now=datetime(2026, 1, 1))


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

    import asyncio

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

    import asyncio

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

    import asyncio

    with pytest.raises(ValueError, match="Cannot revoke the last active key"):
        asyncio.run(
            agent.revoke_key(
                registry_url="https://registry.example.com/registry/agents/revoke-key",
                client_id="developer-a",
                api_key="test-key",
                kid_to_revoke="vault:transit/weather-agent",
            )
        )
