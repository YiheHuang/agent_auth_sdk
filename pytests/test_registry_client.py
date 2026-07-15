from __future__ import annotations

import asyncio

import httpx
import pytest

from agent_auth import AgentAuthError
from agent_auth._protocol import DevSigner, sign_envelope
from agent_auth._registry import Registry
from agent_auth._types import AgentRecord

AGENT_ID = "agent://127.0.0.1/researcher"


def _metadata() -> dict[str, object]:
    signer = DevSigner(AGENT_ID)
    return AgentRecord(
        AGENT_ID,
        "http://127.0.0.1/invoke",
        ("research",),
        signer.kid,
        signer.public_key,
        "2026-07-15T12:00:00Z",
    ).as_dict()


def test_registry_resolve_cache_etag_health_and_mutation(monkeypatch) -> None:
    calls: list[httpx.Request] = []
    metadata = _metadata()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ok"})
        if request.method == "POST":
            assert request.headers["authorization"] == "Bearer secret"
            return httpx.Response(200, json={"ok": True})
        if request.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, json=metadata, headers={"ETag": '"v1"'})

    async def scenario() -> None:
        monkeypatch.setenv("AGENT_AUTH_REGISTRY_API_KEY", "secret")
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://registry/")
        registry = Registry("http://registry", strict=False, client_id="team", client=client)
        await registry.start()
        await registry.health()
        first = await registry.resolve(AGENT_ID)
        assert await registry.resolve(AGENT_ID) is first
        assert await registry.resolve(AGENT_ID, refresh=True) is first
        signer = DevSigner(AGENT_ID)
        envelope = await sign_envelope(
            sender=AGENT_ID,
            audience="http://registry",
            call_type="registry.revoke",
            payload={"agent_id": AGENT_ID},
            signer=signer,
        )
        assert await registry.mutate(envelope) == {"ok": True}
        await registry.close()
        await client.aclose()

    asyncio.run(scenario())
    assert sum(request.method == "GET" and request.url.path.endswith("resolve") for request in calls) == 2


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (httpx.Response(404, json={"detail": "missing"}), "AGENT_NOT_FOUND"),
        (httpx.Response(500, json={}), "REGISTRY_UNAVAILABLE"),
        (httpx.Response(200, json=[]), "REGISTRY_UNAVAILABLE"),
        (httpx.Response(200, json={"agent_id": "other"}), "INVALID_METADATA"),
    ],
)
def test_registry_resolve_failures(response: httpx.Response, code: str) -> None:
    async def scenario() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _request: response), base_url="http://registry/"
        )
        registry = Registry("http://registry", strict=False, client=client)
        with pytest.raises(AgentAuthError, match=code):
            await registry.resolve(AGENT_ID)
        await client.aclose()

    asyncio.run(scenario())


def test_registry_rejects_subject_mismatch_and_mutation_errors(monkeypatch) -> None:
    metadata = _metadata()
    metadata["agent_id"] = "agent://127.0.0.1/other"
    responses = iter(
        [
            httpx.Response(200, json=metadata),
            httpx.Response(409, json={"detail": "NONCE_REPLAYED"}),
            httpx.Response(200, content=b"not-json"),
        ]
    )

    async def scenario() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _request: next(responses)),
            base_url="http://registry/",
        )
        registry = Registry("http://registry", strict=False, client_id="team", client=client)
        with pytest.raises(AgentAuthError, match="REGISTRY_SUBJECT_MISMATCH"):
            await registry.resolve(AGENT_ID)
        signer = DevSigner(AGENT_ID)
        envelope = await sign_envelope(
            sender=AGENT_ID,
            audience="http://registry",
            call_type="registry.revoke",
            payload={"agent_id": AGENT_ID},
            signer=signer,
        )
        monkeypatch.delenv("AGENT_AUTH_REGISTRY_API_KEY", raising=False)
        with pytest.raises(AgentAuthError, match="REGISTRY_CREDENTIALS_MISSING"):
            await registry.mutate(envelope)
        monkeypatch.setenv("AGENT_AUTH_REGISTRY_API_KEY", "secret")
        with pytest.raises(AgentAuthError, match="NONCE_REPLAYED"):
            await registry.mutate(envelope)
        with pytest.raises(AgentAuthError, match="REGISTRY_UNAVAILABLE"):
            await registry.mutate(envelope)
        await client.aclose()

    asyncio.run(scenario())


def test_registry_dev_record_and_no_service_errors() -> None:
    async def scenario() -> None:
        registry = Registry(None, strict=False)
        record = AgentRecord.from_dict(_metadata())
        registry.add_dev_record(record)
        assert await registry.resolve(AGENT_ID) == record
        with pytest.raises(AgentAuthError, match="REGISTRY_UNAVAILABLE"):
            await registry.health()
        other = "agent://127.0.0.1/other"
        with pytest.raises(AgentAuthError, match="AGENT_NOT_FOUND"):
            await registry.resolve(other)
        await registry.close()

    asyncio.run(scenario())


def test_metadata_requires_exact_value_types() -> None:
    value = _metadata()
    value["kid"] = 1
    with pytest.raises(AgentAuthError, match="INVALID_METADATA"):
        AgentRecord.from_dict(value)
    value = _metadata()
    value["capabilities"] = [1]
    with pytest.raises(AgentAuthError, match="INVALID_METADATA"):
        AgentRecord.from_dict(value)
