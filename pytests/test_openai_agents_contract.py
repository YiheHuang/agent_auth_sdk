from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from agents import Agent, Model, ModelResponse, Runner, Usage, function_tool, set_tracing_disabled
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from agent_auth_sdk.integrations.openai_agents import AuthenticatedOpenAIAgents, OpenAIAgentsAuthConfig


class _StaticModel(Model):
    """无需网络的真实 OpenAI Agents Model 契约实现。"""

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


@pytest.mark.anyio
async def test_real_openai_agent_runner_and_function_tool_contract(tmp_path) -> None:
    set_tracing_disabled(True)
    auth = await AuthenticatedOpenAIAgents.from_config(
        OpenAIAgentsAuthConfig(
            roles=("coordinator", "security"),
            runtime_dir=tmp_path / "runtime",
        )
    )
    specialist = Agent(name="security", instructions="Return a deterministic result.", model=_StaticModel())

    result = await auth.call_local_agent(
        source_role="coordinator",
        target_role="security",
        target_agent=specialist,
        payload={"task": "review this input"},
        runner=Runner.run,
    )

    assert result == "authenticated result"
    wrapped = auth.wrap_tool(
        source_role="coordinator",
        target_role="security",
        target_agent=specialist,
        runner=Runner.run,
    )
    tool = function_tool(
        wrapped,
        name_override="call_security_agent",
        description_override="Call the authenticated security agent.",
    )
    coordinator = Agent(name="coordinator", instructions="Use authenticated tools.", tools=[tool])
    assert coordinator.tools[0].name == "call_security_agent"
