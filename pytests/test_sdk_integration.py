from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agent_auth_registry.app import create_app as create_registry_app
from agent_auth_registry.storage import RegistryStore
from agent_auth_sdk import (
    AgentInstance,
    AgentKey,
    AgentMetadata,
    FileMetadataCache,
    InMemoryNonceStore,
    VerificationConfig,
    render_agent_metadata,
    resolve_agent,
    sign_http_request,
    verify_agent_message,
    verify_http_request,
)
from agent_auth_sdk.config import MetadataResolverConfig, STRICT_PROFILE, TEST_PROFILE
from agent_auth_sdk.registry_security import hash_api_key, sign_registry_publish_request
from agent_auth_sdk.vault_kms import VaultKmsConfig, resolve_vault_public_key


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


def create_metadata_app(metadata: dict) -> FastAPI:
    app = FastAPI()

    @app.get("/.well-known/agent.json")
    async def get_metadata() -> JSONResponse:
        return JSONResponse(metadata)

    return app


@pytest.fixture
def registry_env(tmp_path, monkeypatch):
    db_path = tmp_path / "registry.sqlite3"
    public_path = tmp_path / ".well-known" / "agent.json"
    monkeypatch.setenv("AGENT_REGISTRY_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENT_REGISTRY_PATH", str(public_path))
    monkeypatch.setenv("AGENT_REGISTRY_ALLOWED_SKEW_SECONDS", "300")
    return db_path, public_path


def seed_developer(db_path, *, developer_id: str = "dev-1", client_id: str = "developer-a", api_key: str = "secret-api-key") -> None:
    RegistryStore(db_path).create_developer(
        developer_id=developer_id,
        client_id=client_id,
        api_key_hash=hash_api_key(api_key),
    )


def maybe_kms_test_config() -> VaultKmsConfig | None:
    vault_addr = os.getenv("AGENT_AUTH_TEST_VAULT_ADDR")
    vault_token = os.getenv("AGENT_AUTH_TEST_VAULT_TOKEN")
    vault_token_file = os.getenv("AGENT_AUTH_TEST_VAULT_TOKEN_FILE")
    transit_mount = os.getenv("AGENT_AUTH_TEST_VAULT_TRANSIT_MOUNT") or "transit"
    key_name = os.getenv("AGENT_AUTH_TEST_VAULT_KEY_NAME") or os.getenv("AGENT_AUTH_TEST_KMS_KEY_ID")
    if not vault_addr or not (vault_token_file or vault_token) or not key_name:
        return None
    return VaultKmsConfig(
        vault_addr=vault_addr,
        transit_mount=transit_mount,
        key_name=key_name,
        vault_token_file=vault_token_file,
        vault_token=vault_token,
        allow_insecure_raw_token=bool(vault_token),
        namespace=os.getenv("AGENT_AUTH_TEST_VAULT_NAMESPACE") or None,
        verify=os.getenv("AGENT_AUTH_TEST_VAULT_CA_CERT") or True,
        kid=os.getenv("AGENT_AUTH_TEST_KMS_KID") or f"vault:{transit_mount}/{key_name}",
    )


@pytest.mark.anyio
async def test_metadata_discovery_and_verification_success() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    metadata = render_agent_metadata(
        agent_id="agent://127.0.0.1:9001/publisher",
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=["agent-auth"],
        keys=[AgentKey(kid="vault:test", alg="ES256", public_key_pem=public_pem)],
        environment="test",
    ).model_dump(mode="json")
    transport = httpx.ASGITransport(app=create_metadata_app(metadata))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        signer = _TestEs256Signer(private_pem, kid="vault:test")
        signed = await sign_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            body={"hello": "world"},
            agent_id="agent://127.0.0.1:9001/publisher",
            signer=signer,
        )
        result = await verify_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            headers=signed.headers,
            body={"hello": "world"},
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            cache=FileMetadataCache("runtime/test_metadata_cache.sqlite3"),
            config=VerificationConfig(profile=TEST_PROFILE),
            now=datetime.now(timezone.utc),
        )
        assert result.ok is True


@pytest.mark.anyio
async def test_replay_request_rejected() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    metadata = render_agent_metadata(
        agent_id="agent://127.0.0.1:9001/publisher",
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=[],
        keys=[AgentKey(kid="vault:test", alg="ES256", public_key_pem=public_pem)],
        environment="test",
    ).model_dump(mode="json")
    transport = httpx.ASGITransport(app=create_metadata_app(metadata))
    nonce_store = InMemoryNonceStore()
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        signer = _TestEs256Signer(private_pem, kid="vault:test")
        signed = await sign_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            body={"hello": "world"},
            agent_id="agent://127.0.0.1:9001/publisher",
            signer=signer,
            nonce="nonce-1",
        )
        first = await verify_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            headers=signed.headers,
            body={"hello": "world"},
            nonce_store=nonce_store,
            http_client=client,
            config=VerificationConfig(profile=TEST_PROFILE),
        )
        second = await verify_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            headers=signed.headers,
            body={"hello": "world"},
            nonce_store=nonce_store,
            http_client=client,
            config=VerificationConfig(profile=TEST_PROFILE),
        )
        assert first.ok is True
        assert second.ok is False
        assert second.code == "NONCE_REPLAYED"


@pytest.mark.anyio
async def test_strict_profile_rejects_ip_host_metadata() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    metadata = render_agent_metadata(
        agent_id="agent://127.0.0.1:9001/publisher",
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=[],
        keys=[AgentKey(kid="vault:test", alg="ES256", public_key_pem=public_pem)],
        environment="test",
    ).model_dump(mode="json")
    transport = httpx.ASGITransport(app=create_metadata_app(metadata))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        signer = _TestEs256Signer(private_pem, kid="vault:test")
        signed = await sign_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            body={"hello": "world"},
            agent_id="agent://127.0.0.1:9001/publisher",
            signer=signer,
        )
        result = await verify_http_request(
            method="POST",
            url="http://127.0.0.1:8010/invoke",
            headers=signed.headers,
            body={"hello": "world"},
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            config=VerificationConfig(profile=STRICT_PROFILE),
        )
        assert result.ok is False


@pytest.mark.anyio
async def test_signed_agent_message_can_be_verified_via_well_known_metadata() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=["agent-auth"],
        environment="test",
        signer=_TestEs256Signer(private_pem, kid="vault:test"),
        public_key_pem=public_pem,
        kid="vault:test",
        alg="ES256",
    )
    assert agent.metadata is not None
    transport = httpx.ASGITransport(app=create_metadata_app(agent.metadata.model_dump(mode="json")))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        message = await agent.sign_message(
            payload={"hello": "world"},
            recipient="agent://127.0.0.1:8010/verifier",
            message_type="chat.message",
        )
        result = await verify_agent_message(
            message=message,
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            config=VerificationConfig(profile=TEST_PROFILE),
            now=datetime.now(timezone.utc),
        )
        assert result.ok is True
        assert result.message is not None
        assert result.message.payload == {"hello": "world"}


@pytest.mark.anyio
async def test_secure_publish_to_registry_and_resolve_from_registry(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path)
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish", "sign", "verify"],
        environment="prod",
        signer=_TestEs256Signer(private_pem, kid="vault:test"),
        public_key_pem=public_pem,
        kid="vault:test",
        alg="ES256",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        publish_result = await agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-api-key",
            http_client=client,
        )
        assert publish_result["ok"] is True

        resolved = await resolve_agent(
            agent.agent_id,
            profile=TEST_PROFILE,
            http_client=client,
            config=MetadataResolverConfig(
                profile=TEST_PROFILE,
                registry_url="http://registry.local/.well-known/agent.json",
            ),
        )
        assert resolved.metadata.agent_id == agent.agent_id
        assert resolved.metadata.organization == "FDU"


@pytest.mark.anyio
async def test_publish_rejects_wrong_owner(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path, developer_id="dev-1", client_id="developer-a", api_key="secret-a")
    seed_developer(db_path, developer_id="dev-2", client_id="developer-b", api_key="secret-b")
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(private_pem, kid="vault:test"),
        public_key_pem=public_pem,
        kid="vault:test",
        alg="ES256",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        await agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-a",
            http_client=client,
        )
        response = await client.post(
            "http://registry.local/registry/agents/publish",
            json={
                "agent_id": agent.agent_id,
                "metadata": agent.metadata.model_dump(mode="json"),
                "publish_intent": "upsert_metadata",
            },
            headers={
                "authorization": "Bearer secret-b",
                **(
                    await sign_registry_publish_request(
                        path="/registry/agents/publish",
                        host="registry.local",
                        body={
                            "agent_id": agent.agent_id,
                            "metadata": agent.metadata.model_dump(mode="json"),
                            "publish_intent": "upsert_metadata",
                        },
                        agent_id=agent.agent_id,
                        client_id="developer-b",
                        signer=agent.signer,
                    )
                ).headers,
            },
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "OWNER_MISMATCH"


@pytest.mark.anyio
async def test_publish_rejects_when_only_api_key_is_stolen(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path)
    legit_private_pem, legit_public_pem = _generate_es256_pem_pair()
    rogue_private_pem, rogue_public_pem = _generate_es256_pem_pair()
    legit_agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(legit_private_pem, kid="vault:legit"),
        public_key_pem=legit_public_pem,
        kid="vault:legit",
        alg="ES256",
    )
    rogue_agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(rogue_private_pem, kid="vault:rogue"),
        public_key_pem=rogue_public_pem,
        kid="vault:rogue",
        alg="ES256",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        await legit_agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-api-key",
            http_client=client,
        )
        response = await client.post(
            "http://registry.local/registry/agents/publish",
            json={
                "agent_id": legit_agent.agent_id,
                "metadata": rogue_agent.metadata.model_dump(mode="json"),
                "publish_intent": "upsert_metadata",
            },
            headers={
                "authorization": "Bearer secret-api-key",
                **(
                    await sign_registry_publish_request(
                        path="/registry/agents/publish",
                        host="registry.local",
                        body={
                            "agent_id": legit_agent.agent_id,
                            "metadata": rogue_agent.metadata.model_dump(mode="json"),
                            "publish_intent": "upsert_metadata",
                        },
                        agent_id=legit_agent.agent_id,
                        client_id="developer-a",
                        signer=rogue_agent.signer,
                    )
                ).headers,
            },
        )
        assert response.status_code in {401, 409}


@pytest.mark.anyio
async def test_rotate_key_succeeds_and_old_key_becomes_inactive(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path)
    current_private_pem, current_public_pem = _generate_es256_pem_pair()
    new_private_pem, new_public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(current_private_pem, kid="vault:main"),
        public_key_pem=current_public_pem,
        kid="vault:main",
        alg="ES256",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        await agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-api-key",
            http_client=client,
        )
        result = await agent.rotate_key(
            registry_url="http://registry.local/registry/agents/rotate-key",
            client_id="developer-a",
            api_key="secret-api-key",
            new_signer=_TestEs256Signer(new_private_pem, kid="vault:next"),
            new_public_key_pem=new_public_pem,
            new_kid="vault:next",
            http_client=client,
        )
        assert result["ok"] is True
        store = RegistryStore(db_path)
        entry = store.get_registry_entry(agent.agent_id)
        assert entry is not None
        metadata = AgentMetadata.model_validate_json(entry.metadata_json)
        assert any(key.kid == "vault:main" and key.status == "inactive" for key in metadata.keys)
        assert any(key.kid == "vault:next" and key.status == "active" for key in metadata.keys)


@pytest.mark.anyio
async def test_rotate_key_rejects_missing_new_key_proof(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path)
    current_private_pem, current_public_pem = _generate_es256_pem_pair()
    _, new_public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(current_private_pem, kid="vault:main"),
        public_key_pem=current_public_pem,
        kid="vault:main",
        alg="ES256",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        await agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-api-key",
            http_client=client,
        )
        payload = {
            "agent_id": agent.agent_id,
            "new_key": AgentKey(kid="vault:next", alg="ES256", public_key_pem=new_public_pem).model_dump(mode="json"),
            "new_key_proof_headers": {},
        }
        signed = await sign_registry_publish_request(
            path="/registry/agents/rotate-key",
            host="registry.local",
            body=payload,
            agent_id=agent.agent_id,
            client_id="developer-a",
            signer=agent.signer,
        )
        response = await client.post(
            "http://registry.local/registry/agents/rotate-key",
            json=payload,
            headers={"authorization": "Bearer secret-api-key", **signed.headers},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "NEW_KEY_PROOF_REQUIRED"


@pytest.mark.anyio
async def test_rotate_key_rejects_invalid_new_key_proof(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path)
    current_private_pem, current_public_pem = _generate_es256_pem_pair()
    wrong_private_pem, _ = _generate_es256_pem_pair()
    _, new_public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(current_private_pem, kid="vault:main"),
        public_key_pem=current_public_pem,
        kid="vault:main",
        alg="ES256",
    )
    new_key = AgentKey(kid="vault:next", alg="ES256", public_key_pem=new_public_pem)
    from agent_auth_sdk import sign_registry_new_key_proof

    proof = await sign_registry_new_key_proof(
        agent_id=agent.agent_id,
        new_key=new_key,
        client_id="developer-a",
        host="registry.local",
        signer=_TestEs256Signer(wrong_private_pem, kid="vault:next"),
    )
    payload = {
        "agent_id": agent.agent_id,
        "new_key": new_key.model_dump(mode="json"),
        "new_key_proof_headers": proof.headers,
    }
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        await agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-api-key",
            http_client=client,
        )
        signed = await sign_registry_publish_request(
            path="/registry/agents/rotate-key",
            host="registry.local",
            body=payload,
            agent_id=agent.agent_id,
            client_id="developer-a",
            signer=agent.signer,
        )
        response = await client.post(
            "http://registry.local/registry/agents/rotate-key",
            json=payload,
            headers={"authorization": "Bearer secret-api-key", **signed.headers},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "NEW_KEY_PROOF_INVALID"


@pytest.mark.anyio
async def test_publish_timestamp_expired_is_rejected(registry_env) -> None:
    db_path, _ = registry_env
    seed_developer(db_path)
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish"],
        environment="prod",
        signer=_TestEs256Signer(private_pem, kid="vault:test"),
        public_key_pem=public_pem,
        kid="vault:test",
        alg="ES256",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    payload = {
        "agent_id": agent.agent_id,
        "metadata": agent.metadata.model_dump(mode="json"),
        "publish_intent": "upsert_metadata",
    }
    signed = await sign_registry_publish_request(
        path="/registry/agents/publish",
        host="registry.local",
        body=payload,
        agent_id=agent.agent_id,
        client_id="developer-a",
        signer=agent.signer,
        timestamp=(datetime.now(timezone.utc) - timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        response = await client.post(
            "http://registry.local/registry/agents/publish",
            json=payload,
            headers={"authorization": "Bearer secret-api-key", **signed.headers},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "TIMESTAMP_EXPIRED"


@pytest.mark.anyio
async def test_real_vault_publish_and_resolve_from_registry(registry_env) -> None:
    kms_config = maybe_kms_test_config()
    if kms_config is None:
        pytest.skip(
            "Real Vault integration requires AGENT_AUTH_TEST_VAULT_ADDR, AGENT_AUTH_TEST_VAULT_TOKEN_FILE, and AGENT_AUTH_TEST_VAULT_KEY_NAME",
        )
    db_path, _ = registry_env
    seed_developer(db_path)
    key_info = resolve_vault_public_key(kms_config)
    agent = AgentInstance.from_vault(
        domain="demo.example.com",
        name="kms-agent",
        organization="FDU",
        endpoint="https://demo.example.com/invoke",
        vault_addr=kms_config.vault_addr,
        vault_token_file=kms_config.vault_token_file,
        vault_token=kms_config.vault_token,
        allow_insecure_raw_token=kms_config.allow_insecure_raw_token,
        transit_mount=kms_config.transit_mount,
        key_name=kms_config.key_name,
        namespace=kms_config.namespace,
        verify=kms_config.verify,
        kid=kms_config.kid,
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        publish_result = await agent.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="developer-a",
            api_key="secret-api-key",
            http_client=client,
        )
        assert publish_result["ok"] is True
        resolved = await resolve_agent(
            agent.agent_id,
            profile=TEST_PROFILE,
            http_client=client,
            config=MetadataResolverConfig(
                profile=TEST_PROFILE,
                registry_url="http://registry.local/.well-known/agent.json",
            ),
        )
        assert resolved.metadata.agent_id == agent.agent_id
        assert resolved.metadata.keys[0].alg == "ES256"
        assert resolved.metadata.keys[0].public_key_pem == key_info.public_key_pem
