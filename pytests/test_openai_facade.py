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
    AgentAuthorizationError,
    AgentConfigurationError,
    AgentInstance,
    AgentReplayError,
    AgentTransportError,
    AgentVerifier,
    AuthenticatedAgentContext,
    MetadataResolverConfig,
    OpenAIAgentAuth,
    RemoteAgentToolSpec,
    SignedAgentMessage,
    VerificationConfig,
    VerificationFailure,
    VerificationSuccess,
    authenticated_context_from,
)
from agent_auth_sdk.http_utils import canonical_json_bytes
from agent_auth_sdk.integrations.openai_agents import (
    OpenAIAgentsAuthConfig,
    OpenAIAgentsAuthRuntime,
    RemoteAgentEndpoint,
)
from agent_auth_sdk.integrations.openai_facade import _raise_verification, _vault_configuration_error
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
    protected_by_id = auth.protect_tool(review, target="agent://127.0.0.1:8700/security")
    assert await protected_by_id.on_invoke_tool(None, json.dumps({"text": "safe", "severity": 1})) == "1:safe"
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
    assert auth.events()[-1].request_id
    assert auth.drain_events()
    assert auth.events() == []
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
    server_auth.public_base_url = "https://agents.example.com"
    router = server_auth.router()

    @router.endpoint("/invoke", request_model=SecurityRequest)
    async def invoke(context: object, request: SecurityRequest) -> SecurityResult:
        assert context.agent_id == runtime.agent("caller").agent_id
        return SecurityResult(answer=f"reviewed:{request.prompt}")

    app = FastAPI()
    app.include_router(router)
    body = canonical_json_bytes({"prompt": "hello"})
    url = "https://agents.example.com/invoke"
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

    invalid_body = canonical_json_bytes({})
    invalid_signature = await runtime.agent("caller").sign_http(method="POST", url=url, body=invalid_body)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        invalid = await client.post("/invoke", content=invalid_body, headers=invalid_signature.headers)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "REQUEST_SCHEMA_INVALID"

    duplicate_headers = list(signature.headers.items()) + [("x-agent-id", runtime.agent("caller").agent_id)]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        duplicate = await client.post("/invoke", content=body, headers=duplicate_headers)
    assert duplicate.status_code == 400
    assert duplicate.json()["error"]["code"] == "DUPLICATE_SIGNED_HEADER"
    await registry_http.aclose()


@pytest.mark.anyio
async def test_from_env_uses_single_identity_config(tmp_path: Path) -> None:
    config_path = tmp_path / "agent-auth.toml"
    config_path.write_text(
        'identity = "agent://127.0.0.1:8700/caller"\nmode = "local"\nprofile = "test"\n',
        encoding="utf-8",
    )
    auth = await OpenAIAgentAuth.from_env(config_path=config_path)
    assert auth.identity == "caller"
    await auth.__aexit__()


def test_single_identity_config_resolves_relative_ca_and_remote(tmp_path: Path) -> None:
    config_path = tmp_path / "agent-auth.toml"
    config_path.write_text(
        'identity = "agent://agents.example.com/coordinator"\n'
        'endpoint = "https://agents.example.com/invoke"\n'
        'public_base_url = "https://agents.example.com"\n'
        'mode = "vault"\n'
        'profile = "strict"\n'
        "[vault]\n"
        'addr = "https://vault.example.com"\n'
        'token_file = "secrets/token"\n'
        'verify = "ca.pem"\n'
        'key = "coordinator"\n'
        "key_version = 3\n"
        "[remotes.security]\n"
        'agent_id = "agent://security.example.com/reviewer"\n'
        'url = "https://security.example.com/invoke"\n',
        encoding="utf-8",
    )
    config = OpenAIAgentsAuthConfig.from_file(config_path)
    assert config.default_role() == "coordinator"
    assert config.domain == "agents.example.com"
    assert config.endpoint_for("coordinator") == "https://agents.example.com/invoke"
    assert config.vault_verify == str(tmp_path / "ca.pem")
    assert config.vault_key_versions == {"coordinator": 3}
    assert config.remotes["security"].agent_id == "agent://security.example.com/reviewer"


@pytest.mark.anyio
async def test_injected_http_client_is_not_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_from_vault(**kwargs: object) -> AgentInstance:
        return OpenAIAgentAuth.local(identity=str(kwargs["name"])).agent

    monkeypatch.setattr(AgentInstance, "from_vault", staticmethod(fake_from_vault))
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    config = OpenAIAgentsAuthConfig(
        roles=("caller",),
        mode="vault",
        domain="agents.example.com",
        profile="strict",
        vault_addr="https://vault.example.com",
        vault_token_file="/secure/token",
        vault_key_names={"caller": "caller-key"},
        vault_key_versions={"caller": 1},
    )
    auth = await OpenAIAgentAuth.from_config(config, http_client=client)
    await auth.__aexit__()
    assert client.is_closed is False
    await client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "code", "error_type"),
    [
        (401, "SIGNATURE_INVALID", AgentAuthenticationError),
        (403, "CAPABILITY_DENIED", AgentAuthorizationError),
        (409, "NONCE_REPLAYED", AgentReplayError),
        (503, "UPSTREAM_UNAVAILABLE", AgentTransportError),
    ],
)
async def test_remote_client_maps_safe_error_envelope(
    status: int,
    code: str,
    error_type: type[Exception],
) -> None:
    auth = OpenAIAgentAuth.local(identity="caller")

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            json={
                "error": {
                    "code": code,
                    "message": "Request rejected",
                    "request_id": "req-1",
                }
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    from agent_auth_sdk.remote import RemoteAgentClient

    remote = RemoteAgentClient(sender=auth.agent, verifier=auth.verifier, http_client=client)
    with pytest.raises(error_type) as captured:
        await remote.call(
            target_url="https://security.example.com/invoke",
            target_agent_id="agent://security.example.com/reviewer",
            payload={"prompt": "review"},
            request_id="req-1",
        )
    assert isinstance(captured.value, (AgentAuthenticationError, AgentAuthorizationError, AgentTransportError))
    assert captured.value.code == code
    assert captured.value.request_id == "req-1"
    await client.aclose()


@pytest.mark.anyio
async def test_remote_tool_alias_and_invalid_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = OpenAIAgentsAuthConfig(
        roles=("caller",),
        remotes={
            "security": RemoteAgentEndpoint(
                agent_id="agent://security.example.com/reviewer",
                url="https://security.example.com/invoke",
            )
        },
    )
    auth = await OpenAIAgentAuth.from_config(config_path)

    async def fake_call(_: object, **__: object) -> dict[str, str]:
        return {"answer": "ok"}

    monkeypatch.setattr("agent_auth_sdk.integrations.openai_facade.RemoteAgentClient.call", fake_call)
    tool = auth.remote_tool("security", input_type=SecurityRequest, output_type=SecurityResult)
    assert await tool.on_invoke_tool(None, '{"prompt":"review"}') == SecurityResult(answer="ok")
    with pytest.raises(AgentAuthenticationError, match="schema"):
        await tool.on_invoke_tool(None, "{}")
    with pytest.raises(AgentConfigurationError, match="not configured"):
        auth.remote_tool("missing", input_type=SecurityRequest)
    await auth.__aexit__()


def test_facade_stable_failure_mapping_and_vault_diagnostics() -> None:
    assert _raise_verification(VerificationSuccess()) is None
    failures = [
        ("NONCE_REPLAYED", AgentReplayError),
        ("METADATA_FETCH_FAILED", AgentAuthenticationError),
        ("POLICY_REJECTED", AgentAuthorizationError),
        ("SIGNATURE_INVALID", AgentAuthenticationError),
    ]
    for code, error_type in failures:
        with pytest.raises(error_type):
            _raise_verification(VerificationFailure(code=code, reason="rejected"))

    diagnostics = [
        (ValueError("vault_addr must use HTTPS"), "VAULT_TLS_REQUIRED"),
        (ValueError("certificate verify failed"), "VAULT_CA_INVALID"),
        (ValueError("Vault token file permissions are too broad"), "VAULT_TOKEN_PERMISSION_DENIED"),
        (ValueError("Vault token file is empty"), "VAULT_TOKEN_FILE_INVALID"),
        (ValueError("public key version 9 missing"), "VAULT_KEY_VERSION_NOT_FOUND"),
        (type("InvalidPath", (Exception,), {})("missing"), "VAULT_KEY_NOT_FOUND"),
        (type("Forbidden", (Exception,), {})("denied"), "VAULT_PERMISSION_DENIED"),
        (type("ConnectionError", (Exception,), {})("down"), "VAULT_UNAVAILABLE"),
        (RuntimeError("unknown"), "VAULT_CONFIGURATION_INVALID"),
    ]
    for error, code in diagnostics:
        assert _vault_configuration_error(error, "caller").code == code


def test_authenticated_context_helpers() -> None:
    context = AuthenticatedAgentContext(
        agent_id="agent://agents.example.com/caller",
        kid="kid-1",
        capabilities=("review",),
    )
    assert context.has_capability("review") is True
    assert context.has_capability("admin") is False
    assert authenticated_context_from(context) is context
    assert authenticated_context_from(type("Wrapper", (), {"context": context})()) is context
    assert authenticated_context_from(type("State", (), {"agent_auth": context})()) is context
    request = type("Request", (), {"state": type("State", (), {"agent_auth": context})()})()
    assert authenticated_context_from(request) is context
    assert authenticated_context_from(object()) is None


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
        vault_key_versions={"caller": 1, "security": 1},
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
