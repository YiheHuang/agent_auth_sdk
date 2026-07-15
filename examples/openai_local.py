"""无外部服务的真实 OpenAI Agents SDK 契约示例。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from agents import Agent, Model, ModelResponse, Usage, function_tool, handoff, set_tracing_disabled
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from agent_auth import AgentAuth


class OfflineModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return ModelResponse(
            output=[
                ResponseOutputMessage(
                    id="offline",
                    role="assistant",
                    status="completed",
                    content=[ResponseOutputText(annotations=[], text="authenticated result", type="output_text")],
                    type="message",
                )
            ],
            usage=Usage(),
            response_id="offline",
        )

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        raise NotImplementedError


class ToolCallingModel(OfflineModel):
    def __init__(self, tool_name: str, arguments: dict[str, Any]) -> None:
        self.tool_name = tool_name
        self.arguments = arguments
        self.called = False

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        if not self.called:
            self.called = True
            return ModelResponse(
                output=[
                    ResponseFunctionToolCall(
                        arguments=json.dumps(self.arguments),
                        call_id=f"call-{self.tool_name}",
                        name=self.tool_name,
                        type="function_call",
                        status="completed",
                    )
                ],
                usage=Usage(),
                response_id=f"response-{self.tool_name}",
            )
        return await super().get_response(*args, **kwargs)


async def main() -> None:
    set_tracing_disabled(True)
    with TemporaryDirectory(prefix="agent-auth-") as directory:
        config = Path(directory) / "agent-auth.toml"
        config.write_text(
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

        @function_tool
        async def current_time() -> str:
            """Return deterministic demo time."""

            return "12:00 UTC"

        async def run(label: str, coordinator: Agent, researcher: Agent) -> None:
            async with AgentAuth(config) as auth:
                auth.bind({"coordinator": coordinator, "researcher": researcher})
                result = await auth.run(coordinator, "Demonstrate Agent Auth")
                print(f"{label}: {result.final_output}")

        researcher = Agent(name="researcher", instructions="Research.", model=OfflineModel())
        await run(
            "direct",
            Agent(name="coordinator", instructions="Coordinate.", model=OfflineModel()),
            researcher,
        )
        await run(
            "function_tool",
            Agent(
                name="coordinator",
                instructions="Call time.",
                model=ToolCallingModel("current_time", {}),
                tools=[current_time],
            ),
            researcher,
        )
        await run(
            "agent_as_tool",
            Agent(
                name="coordinator",
                instructions="Delegate.",
                model=ToolCallingModel("research", {"input": "topic"}),
                tools=[researcher.as_tool("research", "Run authenticated research")],
            ),
            researcher,
        )
        await run(
            "handoff",
            Agent(
                name="coordinator",
                instructions="Transfer.",
                model=ToolCallingModel("transfer_to_researcher", {}),
                handoffs=[handoff(researcher)],
            ),
            researcher,
        )


if __name__ == "__main__":
    asyncio.run(main())
