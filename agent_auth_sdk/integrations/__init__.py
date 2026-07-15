"""Optional integrations for popular agent frameworks."""

from .openai_agents import (
    AuthenticatedOpenAIAgents,
    OpenAIAgentsAuthConfig,
    OpenAIAgentsAuthRuntime,
    RemoteAgentEndpoint,
)
from .openai_facade import AuthenticatedTool, OpenAIAgentAuth, RemoteAgentToolSpec
from .openai_fastapi import AgentAuthRouter, authenticated_agent

__all__ = [
    "AuthenticatedOpenAIAgents",
    "OpenAIAgentsAuthConfig",
    "OpenAIAgentsAuthRuntime",
    "RemoteAgentEndpoint",
    "OpenAIAgentAuth",
    "AuthenticatedTool",
    "RemoteAgentToolSpec",
    "AgentAuthRouter",
    "authenticated_agent",
]
