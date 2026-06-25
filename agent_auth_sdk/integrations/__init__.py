"""Optional integrations for popular agent frameworks."""

from .openai_agents import (
    AuthenticatedOpenAIAgents,
    OpenAIAgentsAuthConfig,
    OpenAIAgentsAuthRuntime,
)

__all__ = [
    "AuthenticatedOpenAIAgents",
    "OpenAIAgentsAuthConfig",
    "OpenAIAgentsAuthRuntime",
]
