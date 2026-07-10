"""metadata 发现、校验与公钥选择逻辑。"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import UTC, datetime
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from .config import STRICT_PROFILE, DiscoveryMode, MetadataResolverConfig, RuntimeProfile
from .errors import AgentIdentityError, MetadataValidationError
from .identity import assert_subject_match, build_agent_id, parse_agent_id
from .models import AgentKey, AgentMetadata, AgentRegistryDocument, ResolveResult
from .stores import MetadataCache


def _split_host_port(host: str) -> tuple[str, str | None]:
    parsed = urlparse(f"//{host}")
    try:
        port = str(parsed.port) if parsed.port is not None else None
    except ValueError:
        return host, None
    return parsed.hostname or host, port


def _is_ip_host(host: str) -> bool:
    hostname, _ = _split_host_port(host)
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return hostname.lower() == "localhost"


def metadata_url_for_agent(agent_id: str, profile: RuntimeProfile) -> str:
    parsed = parse_agent_id(agent_id)
    scheme = "http" if profile.allow_http and _is_ip_host(parsed.host) else "https"
    return f"{scheme}://{parsed.host}/.well-known/agent.json"


def validate_metadata(metadata: AgentMetadata, profile: RuntimeProfile) -> None:
    assert_subject_match(metadata.agent_id, metadata.domain)
    if build_agent_id(metadata.domain, metadata.name) != metadata.agent_id:
        raise MetadataValidationError("metadata domain/name do not match agent_id")
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
    profile: RuntimeProfile | None = None,
    http_client: httpx.AsyncClient,
    cache: MetadataCache | None = None,
    config: MetadataResolverConfig | None = None,
) -> ResolveResult:
    config = config or MetadataResolverConfig(profile=profile or STRICT_PROFILE)
    profile = profile or config.profile
    ttl_seconds = config.cache_ttl_seconds or profile.metadata_cache_ttl_seconds
    parse_agent_id(agent_id)

    cached = await cache.get(agent_id) if cache else None
    if cached:
        return cached

    mode = config.effective_discovery_mode
    if mode in {DiscoveryMode.REGISTRY_ONLY, DiscoveryMode.REGISTRY_THEN_DIRECT}:
        if not config.registry_url:
            raise MetadataValidationError("registry_url is required for registry discovery")
        try:
            result = await _resolve_from_registry(
                agent_id,
                registry_url=config.registry_url,
                profile=profile,
                http_client=http_client,
                timeout_seconds=config.request_timeout_seconds,
            )
            if cache:
                await cache.set(agent_id, result, ttl_seconds)
            return result
        except Exception:
            if mode == DiscoveryMode.REGISTRY_ONLY:
                raise

    if mode not in {DiscoveryMode.DIRECT_ONLY, DiscoveryMode.REGISTRY_THEN_DIRECT}:
        raise MetadataValidationError(f"unsupported discovery mode: {mode}")
    url = metadata_url_for_agent(agent_id, profile)
    pinned_ip = await _validate_direct_target(url, profile)
    request_url = _pin_direct_url(url, pinned_ip)
    parsed_direct_url = urlparse(url)
    request_headers = {"host": parsed_direct_url.netloc}
    request_extensions = (
        {"sni_hostname": parsed_direct_url.hostname}
        if parsed_direct_url.scheme == "https" and pinned_ip != parsed_direct_url.hostname
        else None
    )
    try:
        response = await http_client.get(
            request_url,
            headers=request_headers,
            timeout=config.request_timeout_seconds,
            follow_redirects=False,
            extensions=request_extensions,
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and payload.get("registry_type") == "agent_registry":
            document = AgentRegistryDocument.model_validate(payload)
            entry = next((item for item in document.agents if item.agent_id == agent_id), None)
            if entry is None:
                raise MetadataValidationError(f"agent not found in well-known document: {agent_id}")
            metadata = entry.metadata
        else:
            metadata = AgentMetadata.model_validate(payload)
        if metadata.agent_id != agent_id:
            raise MetadataValidationError("resolved metadata agent_id does not match requested agent_id")
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
        raise exc


async def _resolve_from_registry(
    agent_id: str,
    *,
    registry_url: str,
    profile: RuntimeProfile,
    http_client: httpx.AsyncClient,
    timeout_seconds: float,
) -> ResolveResult:
    parsed_url = urlparse(registry_url)
    if profile.allow_http is False and parsed_url.scheme != "https":
        raise MetadataValidationError("registry_url must use https in strict profile")
    if parsed_url.path.endswith("/.well-known/agent.json"):
        request_url = registry_url
    else:
        base_path = parsed_url.path.rstrip("/")
        if not base_path.endswith("/v1/agents/resolve"):
            base_path += "/v1/agents/resolve"
        request_url = urlunparse(parsed_url._replace(path=base_path, query=urlencode({"agent_id": agent_id})))
    response = await http_client.get(request_url, timeout=timeout_seconds, follow_redirects=False)
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict) and payload.get("registry_type") != "agent_registry":
        metadata_payload = payload.get("metadata", payload)
        metadata = AgentMetadata.model_validate(metadata_payload)
        if metadata.agent_id != agent_id:
            raise MetadataValidationError("registry returned a different agent_id")
        validate_metadata(metadata, profile)
        return ResolveResult(
            metadata=metadata,
            resolved_at=datetime.now(UTC),
            etag=response.headers.get("etag"),
            source_url=request_url,
        )
    document = AgentRegistryDocument.model_validate(payload)
    for entry in document.agents:
        if entry.agent_id != agent_id:
            continue
        validate_metadata(entry.metadata, profile)
        assert_subject_match(agent_id, entry.metadata.domain)
        return ResolveResult(
            metadata=entry.metadata,
            resolved_at=datetime.now(UTC),
            etag=response.headers.get("etag"),
            source_url=request_url,
        )
    raise MetadataValidationError(f"agent not found in registry: {agent_id}")


async def _validate_direct_target(url: str, profile: RuntimeProfile) -> str:
    """在直接发现前阻止本地、私网和保留地址目标。"""

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise MetadataValidationError("metadata URL is missing hostname")
    if parsed.username is not None or parsed.password is not None:
        raise MetadataValidationError("metadata URL must not contain userinfo")
    if profile.allow_ip_host:
        return hostname
    if hostname.lower() == "localhost":
        raise MetadataValidationError("localhost metadata target is rejected")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            records = await asyncio.to_thread(socket.getaddrinfo, hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise MetadataValidationError(f"unable to resolve metadata host: {hostname}") from exc
        addresses = {str(record[4][0]) for record in records}
        if not addresses:
            raise MetadataValidationError(f"metadata host has no addresses: {hostname}") from None
        if any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise MetadataValidationError("metadata host resolves to a non-global address") from None
        return sorted(addresses, key=lambda address: (ipaddress.ip_address(address).version, address))[0]
    else:
        if not literal.is_global:
            raise MetadataValidationError("metadata target must use a global address")
        return literal.compressed


def _pin_direct_url(url: str, pinned_ip: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname is None or pinned_ip == hostname:
        return url
    ip = ipaddress.ip_address(pinned_ip)
    host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=host))


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
