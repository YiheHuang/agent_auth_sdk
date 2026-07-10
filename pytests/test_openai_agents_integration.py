from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agent_auth_sdk.cli import app
from agent_auth_sdk.integrations.openai_agents import (
    AuthenticatedOpenAIAgents,
    OpenAIAgentsAuthConfig,
    OpenAIAgentsAuthRuntime,
)


@dataclass(slots=True)
class FakeAgent:
    handler: Callable[[Any], Any]


async def fake_runner(agent: FakeAgent, payload: Any) -> Any:
    return agent.handler(payload)


@pytest.mark.anyio
async def test_explicit_call_agent_records_trusted_event(tmp_path: Path) -> None:
    config = OpenAIAgentsAuthConfig(
        roles=("coordinator", "security"),
        runtime_dir=tmp_path / "runtime",
        capabilities={"coordinator": "review.coordinate", "security": "review.security"},
    )
    auth = await AuthenticatedOpenAIAgents.from_config(config)
    security = FakeAgent(lambda payload: {"handled_by": "security", "review_id": payload["review_id"]})

    result = await auth.call_agent(
        source_role="coordinator",
        target_role="security",
        target_agent=security,
        payload={"review_id": "r1"},
        runner=fake_runner,
    )

    assert result == {"handled_by": "security", "review_id": "r1"}
    assert auth.trusted_events() == ["coordinator -> security -> coordinator verified"]


@pytest.mark.anyio
async def test_disabled_auth_directly_calls_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_AUTH_ENABLED", "0")
    config = OpenAIAgentsAuthConfig(roles=("coordinator", "security"), runtime_dir=tmp_path / "runtime")
    auth = await AuthenticatedOpenAIAgents.from_config(config)
    security = FakeAgent(lambda payload: {"raw": payload["value"]})

    result = await auth.call_agent(
        source_role="coordinator",
        target_role="security",
        target_agent=security,
        payload={"value": 42},
        runner=fake_runner,
    )

    assert result == {"raw": 42}
    assert auth.trusted_events() == []


@pytest.mark.anyio
async def test_tampered_payload_is_rejected(tmp_path: Path) -> None:
    config = OpenAIAgentsAuthConfig(roles=("coordinator", "security"), runtime_dir=tmp_path / "runtime")
    runtime = await OpenAIAgentsAuthRuntime.create(config)
    signed = await runtime.sign_for_role(
        "security",
        payload={"handled_by": "security", "findings": []},
        recipient_role="coordinator",
        message_type="agent.call.result",
    )
    tampered = signed.model_dump(mode="json")
    tampered["payload"]["findings"] = [{"severity": "high", "title": "fake"}]

    result = await runtime.verify_for_role(
        "coordinator",
        tampered,
        required_sender_capability="agent.security",
    )

    assert not result.ok
    assert result.code == "SIGNATURE_INVALID"


def test_config_file_parses_env_and_relative_runtime_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_AUTH_REGISTRY_CLIENT_ID", "dev-client")
    config_path = tmp_path / ".agent-auth" / "agent-auth.toml"
    config_path.parent.mkdir()
    config_path.write_text(
        """
mode = "local"
domain = "127.0.0.1:8700"
organization = "Demo"
runtime_dir = "runtime"
roles = ["coordinator", "security"]

[capabilities]
coordinator = "review.coordinate"
security = "review.security"

[registry]
url = "http://127.0.0.1:8700/.well-known/agent.json"
client_id = "${AGENT_AUTH_REGISTRY_CLIENT_ID}"

[vault]
token_file = "vault/token"
""",
        encoding="utf-8",
    )

    config = OpenAIAgentsAuthConfig.from_file(config_path)

    assert config.roles == ("coordinator", "security")
    assert config.registry_client_id == "dev-client"
    assert config.runtime_dir == config_path.parent / "runtime"
    assert config.vault_token_file == str(config_path.parent / "vault" / "token")
    assert config.capability_for("security") == "review.security"


def test_cli_generates_explicit_integration_files(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "integrate-openai-agents",
            "--project-root",
            str(tmp_path),
            "--roles",
            "coordinator,security",
            "--mode",
            "local",
            "--role-capability",
            "security:review.security",
        ],
    )

    assert result.exit_code == 0
    auth_dir = tmp_path / ".agent-auth"
    assert (auth_dir / "agent-auth.toml").exists()
    assert (auth_dir / "auth_adapter.py").exists()
    report = (auth_dir / "INTEGRATION_REPORT.md").read_text(encoding="utf-8")
    assert "No business source files were modified" in report
    config_text = (auth_dir / "agent-auth.toml").read_text(encoding="utf-8")
    assert '"security" = "review.security"' in config_text
