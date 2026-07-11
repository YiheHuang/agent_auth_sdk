"""真实 OpenAI Agents SDK 契约，无网络、无需 OPENAI_API_KEY。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from tempfile import TemporaryDirectory
from typing import Any

from agents import Agent, Model, ModelResponse, RunContextWrapper, Usage, set_tracing_disabled
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from agent_auth_sdk import OpenAIAgentAuth
from agent_auth_sdk.integrations.openai_agents import OpenAIAgentsAuthConfig


class StaticModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return ModelResponse(
            output=[
                ResponseOutputMessage(
                    id="offline-message",
                    role="assistant",
                    status="completed",
                    content=[
                        ResponseOutputText(annotations=[], text="authenticated offline result", type="output_text")
                    ],
                    type="message",
                )
            ],
            usage=Usage(),
            response_id="offline-response",
        )

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        raise NotImplementedError


async def main() -> None:
    set_tracing_disabled(True)
    with TemporaryDirectory(prefix="agent-auth-openai-") as runtime_dir:
        auth = await OpenAIAgentAuth.from_config(
            OpenAIAgentsAuthConfig(
                roles=("coordinator", "security"),
                runtime_dir=__import__("pathlib").Path(runtime_dir),
            ),
            identity="coordinator",
        )
        specialist = Agent(
            name="security",
            instructions="Return a deterministic security result.",
            model=StaticModel(),
        )
        auth.bind({"security": specialist})
        tool = auth.agent_as_tool(
            specialist,
            tool_name="call_security_agent",
            tool_description="Call the authenticated security agent.",
        )
        result = await tool.on_invoke_tool(RunContextWrapper(context=None), '{"input":"review this input"}')
        print(f"result: {result}")
        print(f"tool: {tool.name}")
        print(f"events: {[event.as_dict() for event in auth.events()]}")
        await auth.__aexit__()


if __name__ == "__main__":
    asyncio.run(main())
