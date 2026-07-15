"""OpenAI Agents 的精简公开入口。

普通项目只需从本模块导入高层 facade 和 FastAPI router；历史多身份
runtime 仍保留在 ``agent_auth_sdk.integrations`` 中，但不属于推荐主路径。
"""

from .auth_context import AuthenticatedAgentContext
from .integrations.openai_facade import OpenAIAgentAuth
from .integrations.openai_fastapi import AgentAuthRouter, authenticated_agent

__all__ = [
    "OpenAIAgentAuth",
    "AgentAuthRouter",
    "AuthenticatedAgentContext",
    "authenticated_agent",
]
