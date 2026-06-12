from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agent_auth_sdk import (
    AgentInstance,
    AgentKey,
    FileMetadataCache,
    InMemoryNonceStore,
    LocalPemSigner,
    VerificationConfig,
    generate_ed25519_keypair,
    publish_to_registry,
    render_agent_metadata,
    resolve_agent,
    verify_agent_message,
    sign_http_request,
    verify_http_request,
)
from agent_auth_sdk.config import MetadataResolverConfig, STRICT_PROFILE, TEST_PROFILE
from agent_auth_registry.app import create_app as create_registry_app


def create_metadata_app(metadata: dict) -> FastAPI:
    app = FastAPI()

    @app.get("/.well-known/agent.json")
    async def get_metadata() -> JSONResponse:
        return JSONResponse(metadata)

    return app


@pytest.mark.anyio
async def test_metadata_discovery_and_verification_success() -> None:
    pair = generate_ed25519_keypair(kid="main")
    metadata = render_agent_metadata(
        agent_id="agent://127.0.0.1:9001/publisher",
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=["agent-auth"],
        keys=[AgentKey(kid="main", public_key_pem=pair.public_key_pem, public_key_base64url=pair.public_key_base64url)],
        environment="test",
    ).model_dump(mode="json")
    transport = httpx.ASGITransport(app=create_metadata_app(metadata))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        signer = LocalPemSigner(private_key_pem=pair.private_key_pem, kid_value="main")
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
    pair = generate_ed25519_keypair(kid="main")
    metadata = render_agent_metadata(
        agent_id="agent://127.0.0.1:9001/publisher",
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=[],
        keys=[AgentKey(kid="main", public_key_pem=pair.public_key_pem, public_key_base64url=pair.public_key_base64url)],
        environment="test",
    ).model_dump(mode="json")
    transport = httpx.ASGITransport(app=create_metadata_app(metadata))
    nonce_store = InMemoryNonceStore()
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        signer = LocalPemSigner(private_key_pem=pair.private_key_pem, kid_value="main")
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
    pair = generate_ed25519_keypair(kid="main")
    metadata = render_agent_metadata(
        agent_id="agent://127.0.0.1:9001/publisher",
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=[],
        keys=[AgentKey(kid="main", public_key_pem=pair.public_key_pem, public_key_base64url=pair.public_key_base64url)],
        environment="test",
    ).model_dump(mode="json")
    transport = httpx.ASGITransport(app=create_metadata_app(metadata))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:9001") as client:
        signer = LocalPemSigner(private_key_pem=pair.private_key_pem, kid_value="main")
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
    agent = AgentInstance.create(
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Demo Org",
        endpoint="http://127.0.0.1:9001/invoke",
        capabilities=["agent-auth"],
        environment="test",
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
async def test_publish_to_central_registry_and_resolve_from_registry() -> None:
    agent = AgentInstance.create(
        domain="192.144.228.237",
        name="publisher",
        organization="FDU",
        endpoint="https://192.144.228.237/invoke",
        capabilities=["publish", "sign", "verify"],
        environment="prod",
    )
    assert agent.metadata is not None

    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        publish_result = await publish_to_registry(
            agent.metadata,
            registry_url="http://registry.local/registry/agents",
            publisher="test-suite",
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

