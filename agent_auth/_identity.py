"""严格的 Agent ID 和服务 URL 校验。"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import unquote, urlsplit

from ._errors import AgentAuthError

_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def parse_agent_id(value: str, *, strict: bool = True) -> tuple[str, tuple[str, ...]]:
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "agent" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        if parsed.query or parsed.fragment or parsed.port is not None:
            raise ValueError
        if parsed.hostname != parsed.hostname.encode("idna").decode("ascii").lower():
            raise ValueError
        raw_segments = parsed.path.split("/")[1:]
        if not raw_segments or any(not item for item in raw_segments):
            raise ValueError
        segments = tuple(unquote(item) for item in raw_segments)
        if any(item in {".", ".."} or "/" in item or "\\" in item for item in segments):
            raise ValueError
        canonical = f"agent://{parsed.hostname}/{'/'.join(segments)}"
        if value != canonical:
            raise ValueError
        if strict:
            _reject_non_public_host(parsed.hostname)
        return parsed.hostname, segments
    except (UnicodeError, ValueError) as exc:
        raise AgentAuthError("INVALID_AGENT_ID", "Agent ID must be a canonical agent:// public-DNS URI") from exc


def validate_endpoint(agent_id: str, endpoint: str, *, strict: bool = True) -> None:
    host, _ = parse_agent_id(agent_id, strict=strict)
    try:
        parsed = urlsplit(endpoint)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
            raise ValueError
        if strict and parsed.scheme != "https":
            raise ValueError
        if not strict and parsed.scheme not in {"http", "https"}:
            raise ValueError
        if parsed.hostname.lower() != host:
            raise ValueError
        if not parsed.path.startswith("/"):
            raise ValueError
    except ValueError as exc:
        raise AgentAuthError("INVALID_ENDPOINT", "Endpoint must use the Agent ID host and an allowed scheme") from exc


def validate_service_url(value: str, *, strict: bool = True) -> str:
    try:
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError
        if strict and parsed.scheme != "https":
            raise ValueError
        if not strict and parsed.scheme not in {"http", "https"}:
            raise ValueError
        if strict:
            _reject_non_public_host(parsed.hostname)
        return value.rstrip("/")
    except ValueError as exc:
        raise AgentAuthError("INVALID_URL", "Service URL is not allowed") from exc


def namespace_matches(agent_id: str, domain: str, path_prefix: str) -> bool:
    host, segments = parse_agent_id(agent_id, strict=False)
    normalized = "/" + "/".join(segments)
    prefix = "/" + path_prefix.strip("/")
    return host == domain.lower() and (prefix == "/" or normalized == prefix or normalized.startswith(prefix + "/"))


def _reject_non_public_host(host: str) -> None:
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal")):
        raise ValueError
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
            raise ValueError from None
        return
    else:
        raise ValueError


def resolve_public_host(host: str) -> set[str]:
    """解析远程 endpoint，并拒绝 DNS 指向私网或保留地址。"""

    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            value = str(item[4][0])
            address = ipaddress.ip_address(value)
            if not address.is_global:
                raise AgentAuthError("ENDPOINT_NOT_PUBLIC", "Endpoint DNS resolved to a non-public address")
            addresses.add(value)
    except socket.gaierror as exc:
        raise AgentAuthError("ENDPOINT_DNS_FAILED", "Endpoint DNS resolution failed") from exc
    return addresses
