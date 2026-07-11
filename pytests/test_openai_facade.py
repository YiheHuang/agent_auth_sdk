from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from agents import Agent, FunctionTool
from fastapi import FastAPI
from pydantic import BaseModel

from agent_auth_sdk import (
    TEST_PROFILE,
    AgentAuthenticationError,
    AgentAuthRouter,
    AgentConfigurationError,
    AgentInstance,
    AgentVerifier,
    MetadataResolverConfig,
    OpenAIAgentAuth,
    RemoteAgentToolSpec,
    SignedAgentMessage,
    VerificationConfig,
)
from agent_auth_sdk.http_utils import canonical_json_bytes
from agent_auth_sdk.integrations.openai_agents import OpenAIAgentsAuthConfig, OpenAIAgentsAuthRuntime
from agent_auth_sdk.openai_migration import inspect_openai_project, write_migration_report


@pytest.mark.anyio
async def test_protect_tool_preserves_openai_metadata_and_executes() -> None:
    auth = await OpenAIAgentAuth.from_config(
        OpenAIAgentsAuthConfig(roles=("coordinator", "security")),
        identity="coordinator",
    )

    async def invoke_review(_: object, arguments_json: str) -> str:
        arguments = json.loads(arguments_json)
        return f"{arguments['severity']}:{arguments['text']}"

    review = FunctionTool(
        name="review",
        description="Review text.",
        params_json_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}, "severity": {"type": "integer"}},
            "required": ["text"],
        },
        on_invoke_tool=invoke_review,
    )

    protected = auth.protect_tool(review, target="security")
    assert protected.name == review.name
    assert protected.description == review.description
    assert protected.params_json_schema == review.params_json_schema
    assert protected.is_enabled == review.is_enabled
    assert await protected.on_invoke_tool(None, json.dumps({"text": "safe", "severity": 2})) == "2:safe"
    assert auth.events()[-1].operation == "openai.function_tool"
    assert auth.events()[-1].ok is True
    await auth.__aexit__()


@pytest.mark.anyio
async def test_bind_agent_as_tool_and_authenticated_handoff() -> None:
    auth = await OpenAIAgentAuth.from_config(
        OpenAIAgentsAuthConfig(roles=("coordinator", "security")),
        identity="coordinator",
    )
    security = Agent(name="security", instructions="Return a short result")
    auth.bind({"security": security})

    tool = auth.agent_as_tool(
        security,
        tool_name="security_review",
        tool_description="Authenticated security review",
    )
    assert tool.name == "security_review"
    assert tool.description == "Authenticated security review"

    handoff = auth.authenticated_handoff(security, tool_name="transfer_to_security")
    assert await handoff.on_invoke_handoff(None, "{}") is security
    assert auth.events()[-1].operation == "openai.handoff"
    await auth.__aexit__()


class SecurityRequest(BaseModel):
    prompt: str


class SecurityResult(BaseModel):
    answer: str


@pytest.mark.anyio
async def test_remote_agent_tool_keeps_typed_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    auth = OpenAIAgentAuth.local(identity="caller")

    async def fake_call(_: object, **__: object) -> dict[str, str]:
        return {"answer": "verified"}

    monkeypatch.setattr("agent_auth_sdk.integrations.openai_facade.RemoteAgentClient.call", fake_call)
    tool = auth.remote_agent_tool(
        name="security_review",
        target="agent://agents.example.com/security",
        url="https://security.example.com/invoke",
        input_type=SecurityRequest,
        output_type=SecurityResult,
    )
    assert tool.params_json_schema["required"] == ["prompt"]
    result = await tool.on_invoke_tool(None, '{"prompt":"review"}')
    assert result == SecurityResult(answer="verified")
    batch = auth.remote_agent_tools(
        [
            RemoteAgentToolSpec(
                name="security_review_2",
                target="agent://agents.example.com/security",
                url="https://security.example.com/invoke",
                input_type=SecurityRequest,
            )
        ]
    )
    assert [item.name for item in batch] == ["security_review_2"]


@pytest.mark.anyio
async def test_agent_auth_router_verifies_request_and_signs_response() -> None:
    config = OpenAIAgentsAuthConfig(roles=("caller", "security"))
    runtime = await OpenAIAgentsAuthRuntime.create(config)
    registry_http = httpx.AsyncClient(transport=runtime._registry_transport())
    verifier = AgentVerifier(
        verification_config=VerificationConfig(profile=TEST_PROFILE),
        resolver_config=MetadataResolverConfig(
            profile=TEST_PROFILE,
            registry_url=config.registry_document_url(),
        ),
        http_client=registry_http,
    )
    server_auth = OpenAIAgentAuth.from_components(
        identity="security",
        agent=runtime.agent("security"),
        verifier=verifier,
        profile="test",
    )
    router = AgentAuthRouter(server_auth)

    @router.agent_endpoint("/invoke", request_model=SecurityRequest)
    async def invoke(context: object, request: SecurityRequest) -> SecurityResult:
        assert context.agent_id == runtime.agent("caller").agent_id
        return SecurityResult(answer=f"reviewed:{request.prompt}")

    app = FastAPI()
    app.include_router(router.router)
    body = canonical_json_bytes({"prompt": "hello"})
    url = "http://test/invoke"
    signature = await runtime.agent("caller").sign_http(method="POST", url=url, body=body)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/invoke", content=body, headers=signature.headers)
    assert response.status_code == 200
    message = SignedAgentMessage.model_validate(response.json())
    verified = await verifier.verify_message(
        message=message,
        expected_recipient=runtime.agent("caller").agent_id,
    )
    assert verified.ok is True
    assert message.payload == {"answer": "reviewed:hello"}
    await registry_http.aclose()


@pytest.mark.anyio
async def test_strict_profile_cannot_disable_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_AUTH_ENABLED", "0")
    config = OpenAIAgentsAuthConfig(roles=("caller",), profile="strict")
    with pytest.raises(AgentConfigurationError, match="cannot disable"):
        await OpenAIAgentAuth.from_config(config, identity="caller")


def test_stable_error_never_exposes_details_in_string() -> None:
    error = AgentAuthenticationError(
        "Authentication failed",
        code="SIGNATURE_INVALID",
        details={"safe": "value"},
    )
    assert str(error) == "SIGNATURE_INVALID: Authentication failed"
    assert error.as_dict()["details"] == {"safe": "value"}


@pytest.mark.anyio
async def test_vault_runtime_loads_only_selected_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    loaded: list[str] = []

    def fake_from_vault(**kwargs: object) -> AgentInstance:
        name = str(kwargs["name"])
        loaded.append(name)
        return OpenAIAgentAuth.local(identity=name).agent

    monkeypatch.setattr(AgentInstance, "from_vault", staticmethod(fake_from_vault))
    config = OpenAIAgentsAuthConfig(
        roles=("caller", "security"),
        mode="vault",
        domain="agents.example.com",
        profile="strict",
        vault_addr="https://vault.example.com",
        vault_token_file="/secure/token",
        vault_key_names={"caller": "caller-key", "security": "security-key"},
    )
    auth = await OpenAIAgentAuth.from_config(config, identity="caller")
    assert loaded == ["caller"]
    assert auth.registry_client is None
    await auth.__aexit__()


def test_openai_inspect_and_migrate_are_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from agents import Agent, Runner\n"
        "security = Agent(name='security')\n"
        "tool = security.as_tool(tool_name='security')\n"
        "result = Runner.run_sync(security, 'hello')\n",
        encoding="utf-8",
    )
    before = source.read_bytes()
    findings = inspect_openai_project(tmp_path)
    assert {item.kind for item in findings} >= {"agent", "agent_as_tool", "runner"}
    first = write_migration_report(tmp_path).read_bytes()
    second = write_migration_report(tmp_path).read_bytes()
    assert first == second
    assert source.read_bytes() == before
