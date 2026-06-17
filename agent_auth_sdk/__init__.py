"""Agent Auth SDK — Agent 身份发布、请求签名、消息签名与验签。

提供 6 个核心接口：

1. 创建 Agent Metadata — AgentInstance.from_vault()
2. 发布 Agent 到 Registry — AgentInstance.publish()
3. 签名消息        — AgentInstance.sign_http() / AgentInstance.sign_message()
4. 验签            — verify_http_request() / verify_agent_message()
5. 查询 Metadata 表 — resolve_agent()
6. 轮换 Agent Key  — AgentInstance.rotate_key()

完整接口文档见 docs/API_REFERENCE.md。
"""

from .config import (
    MetadataResolverConfig,
    VerificationConfig,
)
from .agent import AgentInstance
from .messaging import verify_agent_message
from .metadata import resolve_agent
from .stores import (
    FileMetadataCache,
    InMemoryNonceStore,
)
from .verification import verify_http_request

__all__ = [
    # 核心接口
    "AgentInstance",
    "verify_http_request",
    "verify_agent_message",
    "resolve_agent",
    # 必需配置
    "VerificationConfig",
    "MetadataResolverConfig",
    # 必需存储实现
    "InMemoryNonceStore",
    "FileMetadataCache",
]
