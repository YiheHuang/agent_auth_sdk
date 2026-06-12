"""agent_id 的构造和解析逻辑。"""

from __future__ import annotations

from urllib.parse import urlparse

from .errors import AgentIdentityError
from .models import ParsedAgentId


def build_agent_id(host: str, agent_name: str) -> str:
    """按照统一格式生成 agent_id。"""

    if not host:
        raise AgentIdentityError("host is required")
    if not agent_name:
        raise AgentIdentityError("agent_name is required")
    agent_name = agent_name.lstrip("/")
    return f"agent://{host}/{agent_name}"


def parse_agent_id(agent_id: str) -> ParsedAgentId:
    """将 agent_id 解析为 host 和多段路径。"""

    parsed = urlparse(agent_id)
    if parsed.scheme != "agent":
        raise AgentIdentityError(f"Invalid agent_id scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise AgentIdentityError("agent_id is missing host")
    path = parsed.path.lstrip("/")
    if not path:
        raise AgentIdentityError("agent_id is missing agent name")
    segments = tuple(segment for segment in path.split("/") if segment)
    return ParsedAgentId(
        raw=agent_id,
        host=parsed.netloc,
        agent_name=segments[-1],
        path_segments=segments,
    )


def assert_subject_match(agent_id: str, subject_host: str) -> None:
    """确保 metadata 或请求中的 host 与 agent_id 声明一致。"""

    parsed = parse_agent_id(agent_id)
    if parsed.host != subject_host:
        raise AgentIdentityError(
            f"agent_id host mismatch: agent_id={parsed.host}, subject={subject_host}",
        )

