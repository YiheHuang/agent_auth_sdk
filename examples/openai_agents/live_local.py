"""需要 OPENAI_API_KEY；使用真实模型调用 authenticated specialist tool。"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from agents import Agent, Runner

from agent_auth_sdk import OpenAIAgentAuth
from agent_auth_sdk.integrations.openai_agents import OpenAIAgentsAuthConfig


async def main() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("Set OPENAI_API_KEY before running this example")
    auth = await OpenAIAgentAuth.from_config(
        OpenAIAgentsAuthConfig(
            roles=("coordinator", "security"),
            runtime_dir=Path(".agent-auth/runtime-openai-live"),
            capabilities={"coordinator": "review.coordinate", "security": "review.security"},
        ),
        identity="coordinator",
    )
    security = Agent(
        name="security",
        instructions="Review the supplied text and return one concise security observation.",
    )
    auth.bind({"security": security})
    tool = auth.agent_as_tool(
        security,
        tool_name="call_security_agent",
        tool_description="Send input to the authenticated security specialist.",
    )
    coordinator = Agent(
        name="coordinator",
        instructions="Always use call_security_agent, then report its result.",
        tools=[tool],
    )
    result = await Runner.run(coordinator, "Review: never log production API keys.")
    print(result.final_output)
    print([event.as_dict() for event in auth.events()])
    await auth.__aexit__()


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    asyncio.run(main())
