"""agent_id 的构造、规范化和解析逻辑。"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .errors import AgentIdentityError
from .models import ParsedAgentId

_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]+$")


def normalize_agent_host(host: str) -> str:
    """返回 agent identity 使用的规范 host（含可选端口）。"""

    if not host or host.strip() != host or any(char.isspace() for char in host):
        raise AgentIdentityError("host is required and must not contain whitespace")
    if "%" in host or "\\" in host:
        raise AgentIdentityError("host contains ambiguous encoding")
    try:
        parsed = urlsplit(f"//{host}")
        port = parsed.port
    except ValueError as exc:
        raise AgentIdentityError("host contains an invalid port") from exc
    if parsed.username is not None or parsed.password is not None:
        raise AgentIdentityError("userinfo is not allowed in agent host")
    if parsed.path or parsed.query or parsed.fragment:
        raise AgentIdentityError("host must not contain path, query, or fragment")
    hostname = parsed.hostname
    if not hostname:
        raise AgentIdentityError("host is required")
    if hostname.endswith("."):
        raise AgentIdentityError("trailing-dot hostnames are not allowed")
    if port == 0:
        raise AgentIdentityError("host contains an invalid port")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            normalized_hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise AgentIdentityError("host is not valid IDNA") from exc
    else:
        normalized_hostname = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    return f"{normalized_hostname}:{port}" if port is not None else normalized_hostname


def normalize_agent_path_prefix(path_prefix: str) -> str:
    """规范 Registry namespace 的 agent path 前缀。"""

    if not path_prefix or path_prefix == "/":
        return "/"
    raw = path_prefix.strip("/")
    segments = raw.split("/")
    if any(not segment or not _PATH_SEGMENT.fullmatch(segment) for segment in segments):
        raise AgentIdentityError("path prefix contains an invalid segment")
    return "/" + "/".join(segments)


def build_agent_id(host: str, agent_name: str) -> str:
    """按照统一格式生成 agent_id。"""

    if not agent_name:
        raise AgentIdentityError("agent_name is required")
    raw_name = agent_name.strip("/")
    segments = raw_name.split("/")
    if any(not segment or not _PATH_SEGMENT.fullmatch(segment) for segment in segments):
        raise AgentIdentityError("agent_name contains an invalid path segment")
    return f"agent://{normalize_agent_host(host)}/{'/'.join(segments)}"


def parse_agent_id(agent_id: str) -> ParsedAgentId:
    """将 agent_id 解析为 host 和多段路径。"""

    if not isinstance(agent_id, str) or not agent_id:
        raise AgentIdentityError("agent_id is required")
    parsed = urlsplit(agent_id)
    if parsed.scheme != "agent":
        raise AgentIdentityError(f"Invalid agent_id scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise AgentIdentityError("agent_id is missing host")
    if parsed.username is not None or parsed.password is not None:
        raise AgentIdentityError("agent_id must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise AgentIdentityError("agent_id must not contain query or fragment")
    if "\\" in parsed.path or "//" in parsed.path or "%" in parsed.path:
        raise AgentIdentityError("agent_id path is ambiguous")
    path = parsed.path.lstrip("/")
    if not path:
        raise AgentIdentityError("agent_id is missing agent name")
    segments = tuple(path.split("/"))
    if any(not _PATH_SEGMENT.fullmatch(segment) for segment in segments):
        raise AgentIdentityError("agent_id path contains an invalid segment")
    host = normalize_agent_host(parsed.netloc)
    normalized = f"agent://{host}/{'/'.join(segments)}"
    if normalized != agent_id:
        raise AgentIdentityError(f"agent_id is not normalized; expected {normalized}")
    return ParsedAgentId(
        raw=agent_id,
        host=host,
        agent_name=segments[-1],
        path_segments=segments,
    )


def assert_subject_match(agent_id: str, subject_host: str) -> None:
    """确保 metadata 或请求中的 host 与 agent_id 声明一致。"""

    parsed = parse_agent_id(agent_id)
    normalized_subject = normalize_agent_host(subject_host)
    if parsed.host != normalized_subject:
        raise AgentIdentityError(
            f"agent_id host mismatch: agent_id={parsed.host}, subject={normalized_subject}",
        )


def agent_id_matches_namespace(agent_id: str, *, domain: str, path_prefix: str = "/") -> bool:
    """判断 agent_id 是否落在管理员分配的精确 domain/path namespace 中。"""

    parsed = parse_agent_id(agent_id)
    if parsed.host != normalize_agent_host(domain):
        return False
    normalized_prefix = normalize_agent_path_prefix(path_prefix)
    path = "/" + "/".join(parsed.path_segments)
    return normalized_prefix == "/" or path == normalized_prefix or path.startswith(normalized_prefix + "/")


def assert_strict_agent_id(agent_id: str) -> None:
    """拒绝 strict Registry 不允许的 IP、本机和保留名称。"""

    parsed = parse_agent_id(agent_id)
    host = urlsplit(f"//{parsed.host}").hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        lowered = host.lower()
        if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal")):
            raise AgentIdentityError("strict agent_id must not use a local or reserved hostname") from None
    else:
        raise AgentIdentityError("strict agent_id must use a DNS hostname, not an IP address")
