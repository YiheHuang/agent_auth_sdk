from __future__ import annotations

import base64
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from agent_auth_sdk import (
    AgentInstance,
    AgentKey,
    InMemoryNonceStore,
    build_agent_id,
    parse_agent_id,
    render_agent_metadata,
    select_verification_key,
)
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
