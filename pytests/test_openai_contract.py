from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest

_OPENAI_VERSION = tuple(int(part) for part in version("openai-agents").split(".")[:3])
if _OPENAI_VERSION < (0, 18, 2):
    pytest.skip("OpenAI Agents contract tests require 0.18.2+", allow_module_level=True)

from agents import (  # noqa: E402
    Agent,
    Model,
    ModelResponse,
    RunContextWrapper,
    Usage,
    function_tool,
    handoff,
    set_tracing_disabled,
)
from agents.tool_context import ToolContext  # noqa: E402
from openai.types.responses import ResponseOutputMessage, ResponseOutputText  # noqa: E402

from agent_auth import AgentAuth  # noqa: E402


class StaticModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return ModelResponse(
            output=[
                ResponseOutputMessage(
                    id="message-1",
                    role="assistant",
                    status="completed",
                    content=[ResponseOutputText(annotations=[], text="authenticated result", type="output_text")],
                    type="message",
                )
            ],
            usage=Usage(),
            response_id="response-1",
        )

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        raise NotImplementedError


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "agent-auth.toml"
    path.write_text(
        """version=1
mode="dev"
[agents.coordinator]
id="agent://127.0.0.1/coordinator"
endpoint="http://127.0.0.1:8101/invoke"
[agents.researcher]
id="agent://127.0.0.1/researcher"
endpoint="http://127.0.0.1:8102/invoke"
""",
        encoding="utf-8",
    )
    return path


def test_real_runner_run_and_run_sync(tmp_path: Path) -> None:
    set_tracing_disabled(True)
    agent = Agent(name="coordinator", instructions="Return a result.", model=StaticModel())
    auth = AgentAuth(_config(tmp_path)).bind({"coordinator": agent})
    result = asyncio.run(auth.run(agent, "hello"))
    assert result.final_output == "authenticated result"
    asyncio.run(auth.close())

    sync_auth = AgentAuth(_config(tmp_path)).bind({"coordinator": agent})
    assert sync_auth.run_sync(agent, "hello").final_output == "authenticated result"


def test_real_function_tool_agent_as_tool_and_handoff_contract(tmp_path: Path) -> None:
    async def scenario() -> None:
        @function_tool
        async def echo(text: str) -> str:
            """Echo text."""

            return "echo:" + text

        coordinator = Agent(name="coordinator", instructions="Coordinate.")
        researcher = Agent(name="researcher", instructions="Research.")
        agent_tool = researcher.as_tool("research", "Run research")

        async def fake_agent_call(_context: Any, arguments: str) -> str:
            return "research:" + arguments

        agent_tool.on_invoke_tool = fake_agent_call
        transfer = handoff(researcher)
        coordinator.tools = [echo, agent_tool]
        coordinator.handoffs = [transfer]
        auth = AgentAuth(_config(tmp_path)).bind({"coordinator": coordinator, "researcher": researcher})
        async with auth:
            original = {
                field.name: getattr(echo, field.name)
                for field in dataclasses.fields(echo)
                if field.name != "on_invoke_tool"
            }
            await auth._instrument()
            wrapped = coordinator.tools[0]
            assert {
                field.name: getattr(wrapped, field.name)
                for field in dataclasses.fields(wrapped)
                if field.name != "on_invoke_tool"
            } == original
            context = ToolContext(
                context=None,
                tool_name="echo",
                tool_call_id="call-1",
                tool_arguments='{"text":"hello"}',
                agent=coordinator,
            )
            assert await wrapped.on_invoke_tool(context, '{"text":"hello"}') == "echo:hello"
            assert "research" in await coordinator.tools[1].on_invoke_tool(context, '{"input":"topic"}')
            assert await coordinator.handoffs[0].on_invoke_handoff(RunContextWrapper(context=None), "{}") is researcher

        coordinator.handoffs = [researcher]
        shorthand = AgentAuth(_config(tmp_path)).bind({"coordinator": coordinator, "researcher": researcher})
        async with shorthand:
            await shorthand._instrument()
            assert callable(coordinator.handoffs[0].on_invoke_handoff)

    asyncio.run(scenario())
