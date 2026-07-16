from __future__ import annotations

import asyncio
import dataclasses
import weakref
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from agent_auth import AgentAuth, AgentAuthError, AuthContext
from agent_auth._auth import _pin_public_endpoint
from agent_auth._protocol import SignedEnvelope, sign_envelope, verify_envelope


@dataclass
class FakeTool:
    name: str
    description: str
    params_json_schema: dict[str, Any]
    on_invoke_tool: Any
    is_enabled: bool = True
    guardrail: str = "keep"
    _agent_instance: Any = None


@dataclass
class FakeHandoff:
    tool_name: str
    on_invoke_handoff: Any
    _agent_ref: Any
    is_enabled: bool = True


@dataclass
class FakeAgent:
    name: str
    tools: list[Any] = field(default_factory=list)
    handoffs: list[Any] = field(default_factory=list)


class RequestModel(BaseModel):
    text: str


class ResponseModel(BaseModel):
    answer: str


def test_bind_rejects_unknown_and_duplicate(dev_config) -> None:
    auth = AgentAuth(dev_config)
    agent = FakeAgent("a")
    with pytest.raises(AgentAuthError, match="IDENTITY_NOT_CONFIGURED"):
        auth.bind({"missing": agent})
    auth.bind({"coordinator": agent})
    with pytest.raises(AgentAuthError, match="AGENT_ALREADY_BOUND"):
        auth.bind({"researcher": agent})
    with pytest.raises(AgentAuthError, match="IDENTITY_ALREADY_BOUND"):
        auth.bind({"coordinator": FakeAgent("other")})


def test_plain_and_agent_tool_are_authenticated_and_preserve_fields(dev_config) -> None:
    async def scenario() -> None:
        coordinator = FakeAgent("coordinator")
        researcher = FakeAgent("researcher")

        async def invoke(_context: Any, arguments: str) -> str:
            return "result:" + arguments

        plain = FakeTool("plain", "description", {"type": "object"}, invoke)
        delegated = FakeTool("delegate", "agent tool", {"type": "object"}, invoke, _agent_instance=researcher)
        coordinator.tools = [plain, delegated]
        auth = AgentAuth(dev_config).bind({"coordinator": coordinator, "researcher": researcher})
        async with auth:
            await auth._instrument()
            assert coordinator.tools[0].name == plain.name
            assert coordinator.tools[0].guardrail == "keep"
            context = SimpleNamespace(agent=coordinator)
            assert await coordinator.tools[0].on_invoke_tool(context, '{"x":1}') == 'result:{"x":1}'
            assert await coordinator.tools[1].on_invoke_tool(context, '{"x":2}') == 'result:{"x":2}'
            first = coordinator.tools[0]
            await auth._instrument()
            assert coordinator.tools[0] is first

    asyncio.run(scenario())


def test_handoff_is_authenticated(dev_config) -> None:
    async def scenario() -> None:
        coordinator = FakeAgent("coordinator")
        researcher = FakeAgent("researcher")

        async def invoke(_context: Any, _arguments: str) -> FakeAgent:
            return researcher

        coordinator.handoffs = [FakeHandoff("to_researcher", invoke, weakref.ref(researcher))]
        auth = AgentAuth(dev_config).bind({"coordinator": coordinator, "researcher": researcher})
        async with auth:
            await auth._instrument()
            result = await coordinator.handoffs[0].on_invoke_handoff(SimpleNamespace(), '{"reason":"work"}')
            assert result is researcher

    asyncio.run(scenario())


def test_unbound_agent_tool_and_handoff_fail_before_run(dev_config) -> None:
    async def invoke(*_: Any) -> str:
        return "ok"

    coordinator = FakeAgent("coordinator")
    target = FakeAgent("target")
    auth = AgentAuth(dev_config).bind({"coordinator": coordinator})
    coordinator.tools = [FakeTool("delegate", "", {}, invoke, _agent_instance=target)]
    with pytest.raises(AgentAuthError, match="UNBOUND_TARGET_AGENT"):
        asyncio.run(auth._instrument())
    coordinator.tools = []
    coordinator.handoffs = [FakeHandoff("handoff", invoke, weakref.ref(target))]
    with pytest.raises(AgentAuthError, match="UNBOUND_HANDOFF_TARGET"):
        asyncio.run(auth._instrument())


def test_unknown_remote_endpoint_and_unbound_runner_fail(dev_config) -> None:
    auth = AgentAuth(dev_config)
    with pytest.raises(AgentAuthError, match="REMOTE_NOT_CONFIGURED"):
        auth.remote_tool("missing", input_type=RequestModel, output_type=ResponseModel)
    with pytest.raises(AgentAuthError, match="IDENTITY_NOT_CONFIGURED"):
        auth.endpoint("/bad", identity="missing", request=RequestModel, response=ResponseModel)

    class Runner:
        @staticmethod
        async def run(*_args: Any, **_kwargs: Any) -> None:
            return None

    async def scenario() -> None:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("agent_auth._auth._openai_runner", lambda: Runner)
            with pytest.raises(AgentAuthError, match="CALLER_IDENTITY_UNKNOWN"):
                await auth.run(FakeAgent("unknown"), "input")
        await auth.close()

    asyncio.run(scenario())


def test_run_delegates_and_run_sync_guards_event_loop(dev_config, monkeypatch) -> None:
    class Runner:
        @staticmethod
        async def run(agent: Any, value: Any, **kwargs: Any) -> tuple[Any, Any, dict[str, Any]]:
            return agent, value, kwargs

        @staticmethod
        def run_streamed(agent: Any, value: Any, **kwargs: Any) -> tuple[Any, Any, dict[str, Any]]:
            return agent, value, kwargs

    monkeypatch.setattr("agent_auth._auth._openai_runner", lambda: Runner)
    agent = FakeAgent("coordinator")
    auth = AgentAuth(dev_config).bind({"coordinator": agent})
    assert auth.run_sync(agent, "input", max_turns=2) == (agent, "input", {"max_turns": 2})
    with AgentAuth(dev_config).bind({"coordinator": agent}) as sync_auth:
        assert sync_auth.run_sync(agent, "again") == (agent, "again", {})

    async def streamed() -> None:
        stream_auth = AgentAuth(dev_config).bind({"coordinator": agent})
        async with stream_auth:
            assert stream_auth.run_streamed(agent, "stream", max_turns=3) == (
                agent,
                "stream",
                {"max_turns": 3},
            )

    asyncio.run(streamed())

    async def active_loop() -> None:
        with pytest.raises(AgentAuthError, match="SYNC_IN_ASYNC_CONTEXT"):
            auth.run_sync(agent, "input")

    asyncio.run(active_loop())


def test_fastapi_endpoint_and_remote_tool_roundtrip(dev_config) -> None:
    async def scenario() -> None:
        coordinator = FakeAgent("coordinator")
        researcher = FakeAgent("researcher")
        auth = AgentAuth(dev_config).bind({"coordinator": coordinator, "researcher": researcher})
        app = FastAPI()

        @auth.endpoint(
            "/invoke",
            identity="researcher",
            request=RequestModel,
            response=ResponseModel,
        )
        async def invoke(context: AuthContext, request: RequestModel) -> ResponseModel:
            assert context.sender == "agent://127.0.0.1/coordinator"
            return ResponseModel(answer=request.text.upper())

        app.include_router(auth.router)
        await auth._start()
        await auth._http.aclose()
        auth._http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://local")
        direct = await auth.call("coordinator", "researcher", {"text": "direct"})
        assert direct == {"answer": "DIRECT"}
        tool = auth.remote_tool("researcher", input_type=RequestModel, output_type=ResponseModel)
        context = SimpleNamespace(agent=coordinator)
        result = await tool.on_invoke_tool(context, '{"text":"hello"}')
        assert result == ResponseModel(answer="HELLO")
        with pytest.raises(AgentAuthError, match="SCHEMA_INVALID"):
            await tool.on_invoke_tool(context, '{"missing":true}')

        request = await sign_envelope(
            sender=auth._settings.agents["coordinator"].agent_id,
            audience=auth._settings.agents["researcher"].agent_id,
            call_type="agent.call",
            payload={"text": "replay"},
            signer=auth._signers["coordinator"],
        )
        first = await auth._http.post("http://local/invoke", json=request.as_dict())
        second = await auth._http.post("http://local/invoke", json=request.as_dict())
        assert first.status_code == 200
        assert second.status_code == 409
        reply = SignedEnvelope.from_dict(first.json())
        record = await auth._registry.resolve(reply.sender)
        _, payload = verify_envelope(
            reply,
            record=record,
            audience=auth._settings.agents["coordinator"].agent_id,
            nonce_state=auth._nonce_state,
            expected_type="agent.result",
            expected_reply_to=request.id,
        )
        assert payload == {"answer": "REPLAY"}
        await auth.close()

    asyncio.run(scenario())


def test_call_rejects_unknown_source_and_target(dev_config) -> None:
    async def scenario() -> None:
        auth = AgentAuth(dev_config)
        with pytest.raises(AgentAuthError, match="IDENTITY_NOT_CONFIGURED"):
            await auth.call("missing", "researcher", {})
        with pytest.raises(AgentAuthError, match="REMOTE_NOT_CONFIGURED"):
            await auth.call("coordinator", "missing", {})
        with pytest.raises(AgentAuthError, match="PAYLOAD_INVALID"):
            await auth.call("coordinator", "researcher", {"value": float("nan")})
        await auth.close()

    asyncio.run(scenario())


def test_endpoint_rejects_invalid_schema_and_envelope(dev_config) -> None:
    async def scenario() -> None:
        auth = AgentAuth(dev_config)
        app = FastAPI()

        @auth.endpoint("/invoke", identity="researcher", request=RequestModel, response=ResponseModel)
        async def invoke(_context: AuthContext, request: RequestModel) -> ResponseModel:
            return ResponseModel(answer=request.text)

        app.include_router(auth.router)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://local") as client:
            invalid = await client.post("/invoke", json={"bad": True})
            assert invalid.status_code == 400
        await auth.close()

    asyncio.run(scenario())


def test_endpoint_maps_business_authorization_to_stable_403(dev_config) -> None:
    async def scenario() -> None:
        auth = AgentAuth(dev_config)
        app = FastAPI()

        @auth.endpoint("/invoke", identity="researcher", request=RequestModel, response=ResponseModel)
        async def invoke(_context: AuthContext, _request: RequestModel) -> ResponseModel:
            raise AgentAuthError("CAPABILITY_DENIED", "Caller is not authorized")

        app.include_router(auth.router)
        await auth._start()
        request = await sign_envelope(
            sender=auth._settings.agents["coordinator"].agent_id,
            audience=auth._settings.agents["researcher"].agent_id,
            call_type="agent.call",
            payload={"text": "denied"},
            signer=auth._signers["coordinator"],
        )
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://local") as client:
            response = await client.post("/invoke", json=request.as_dict())
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "CAPABILITY_DENIED"
        await auth.close()

    asyncio.run(scenario())


def test_auth_context_is_minimal() -> None:
    assert [field.name for field in dataclasses.fields(AuthContext)] == [
        "sender",
        "kid",
        "capabilities",
        "request_id",
        "call_type",
    ]


def test_production_endpoint_is_pinned_without_losing_host_or_sni(monkeypatch) -> None:
    monkeypatch.setattr("agent_auth._auth.resolve_public_host", lambda _host: {"203.0.113.20", "203.0.113.10"})
    url, host, sni = _pin_public_endpoint("https://agents.example.com:8443/invoke")
    assert url == "https://203.0.113.10:8443/invoke"
    assert host == "agents.example.com:8443"
    assert sni == "agents.example.com"
