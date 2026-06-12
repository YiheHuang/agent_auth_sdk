from __future__ import annotations

from datetime import datetime

import pytest

from agent_identity_sdk import (
    AgentKey,
    InMemoryNonceStore,
    build_agent_id,
    generate_ed25519_keypair,
    parse_agent_id,
    render_agent_metadata,
    select_verification_key,
)
from agent_identity_sdk.config import STRICT_PROFILE, TEST_PROFILE
from agent_identity_sdk.crypto import LocalPemSigner, verify_signature
from agent_identity_sdk.http_utils import build_canonical_request
from agent_identity_sdk.signing import sign_http_request


def test_parse_agent_id_supports_host_port_and_nested_path() -> None:
    parsed = parse_agent_id("agent://127.0.0.1:8010/company/weather/bot")
    assert parsed.host == "127.0.0.1:8010"
    assert parsed.agent_name == "bot"
    assert parsed.path_segments == ("company", "weather", "bot")


def test_build_agent_id() -> None:
    assert build_agent_id("localhost:9000", "assistant") == "agent://localhost:9000/assistant"


@pytest.mark.asyncio
async def test_sign_and_verify_public_key_material() -> None:
    pair = generate_ed25519_keypair(kid="main")
    signer = LocalPemSigner(private_key_pem=pair.private_key_pem, kid_value="main")
    signed = await sign_http_request(
        method="POST",
        url="http://127.0.0.1:8010/invoke",
        body={"hello": "world"},
        agent_id="agent://127.0.0.1:8010/gateway",
        signer=signer,
    )
    assert verify_signature(
        public_key_pem=pair.public_key_pem,
        public_key_base64url=None,
        data=signed.canonical.encode("utf-8"),
        signature_base64url=signed.headers["x-agent-signature"],
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


@pytest.mark.asyncio
async def test_nonce_store_detects_replay() -> None:
    store = InMemoryNonceStore()
    await store.set("a", 600)
    assert await store.has("a") is True

