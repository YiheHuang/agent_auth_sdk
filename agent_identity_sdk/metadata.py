"""metadata 发现、校验与公钥选择逻辑。"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from .config import MetadataResolverConfig, RuntimeProfile, TEST_PROFILE
from .errors import AgentIdentityError, MetadataValidationError
from .identity import assert_subject_match, parse_agent_id
from .models import AgentKey, AgentMetadata, ResolveResult
from .stores import MetadataCache


def _split_host_port(host: str) -> tuple[str, str | None]:
    if host.count(":") == 1 and not host.startswith("["):
        hostname, port = host.split(":", 1)
        return hostname, port
    return host, None


def _is_ip_host(host: str) -> bool:
    hostname, _ = _split_host_port(host)
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return hostname == "localhost"


def metadata_url_for_agent(agent_id: str, profile: RuntimeProfile) -> str:
    parsed = parse_agent_id(agent_id)
    scheme = "http" if profile.allow_http and _is_ip_host(parsed.host) else "https"
    return f"{scheme}://{parsed.host}/.well-known/agent.json"


def validate_metadata(metadata: AgentMetadata, profile: RuntimeProfile) -> None:
    assert_subject_match(metadata.agent_id, metadata.domain)
    endpoint = urlparse(metadata.endpoint)
    if not endpoint.scheme or not endpoint.netloc:
        raise MetadataValidationError("endpoint must be an absolute URL")
    endpoint_is_ip = _is_ip_host(endpoint.netloc)
    if endpoint.scheme != "https":
        if not (profile.allow_http and endpoint.scheme == "http" and endpoint_is_ip):
            raise MetadataValidationError("endpoint must use https in current profile")
    if not profile.allow_ip_host and _is_ip_host(metadata.domain):
        raise MetadataValidationError("IP/localhost host is rejected in strict profile")

    seen_kids: set[str] = set()
    for key in metadata.keys:
        if key.kid in seen_kids:
            raise MetadataValidationError(f"duplicate kid: {key.kid}")
        seen_kids.add(key.kid)


async def resolve_agent(
    agent_id: str,
    *,
    profile: RuntimeProfile = TEST_PROFILE,
    http_client: httpx.AsyncClient,
    cache: MetadataCache | None = None,
    config: MetadataResolverConfig | None = None,
) -> ResolveResult:
    config = config or MetadataResolverConfig(profile=profile)
    ttl_seconds = config.cache_ttl_seconds or profile.metadata_cache_ttl_seconds

    cached = await cache.get(agent_id) if cache else None
    headers: dict[str, str] = {}
    if cached and cached.etag:
        headers["If-None-Match"] = cached.etag

    url = metadata_url_for_agent(agent_id, profile)
    try:
        response = await http_client.get(url, headers=headers, timeout=config.request_timeout_seconds)
        if response.status_code == 304 and cached:
            return cached
        response.raise_for_status()
        metadata = AgentMetadata.model_validate(response.json())
        validate_metadata(metadata, profile)
        assert_subject_match(agent_id, metadata.domain)
        result = ResolveResult(
            metadata=metadata,
            resolved_at=datetime.now(UTC),
            etag=response.headers.get("etag"),
            source_url=url,
        )
        if cache:
            await cache.set(agent_id, result, ttl_seconds)
        return result
    except (httpx.HTTPError, ValueError, AgentIdentityError, MetadataValidationError) as exc:
        if cached:
            return cached
        raise exc


def select_verification_key(
    metadata: AgentMetadata,
    *,
    kid: str,
    now: datetime,
) -> AgentKey:
    reference_now = _ensure_aware(now)
    if kid in metadata.revoked_kids:
        raise MetadataValidationError(f"revoked key: {kid}")
    for key in metadata.keys:
        if key.kid != kid:
            continue
        if key.status != "active":
            continue
        not_before = _ensure_aware(key.not_before) if key.not_before else None
        not_after = _ensure_aware(key.not_after) if key.not_after else None
        if not_before and not_before > reference_now:
            raise MetadataValidationError(f"key not active yet: {kid}")
        if not_after and not_after < reference_now:
            raise MetadataValidationError(f"key expired: {kid}")
        return key
    raise MetadataValidationError(f"verification key not found: {kid}")


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
