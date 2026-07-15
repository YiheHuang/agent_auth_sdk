"""将远程 researcher 直接放入 OpenAI Agent.tools。"""

from __future__ import annotations

from agents import Agent
from pydantic import BaseModel

from agent_auth import AgentAuth


class ResearchRequest(BaseModel):
    topic: str


class ResearchResult(BaseModel):
    summary: str


auth = AgentAuth()
researcher = auth.remote_tool("researcher", input_type=ResearchRequest, output_type=ResearchResult)
coordinator = Agent(name="coordinator", instructions="Use the researcher tool.", tools=[researcher])
auth.bind({"coordinator": coordinator})
