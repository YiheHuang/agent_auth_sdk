"""Explicit OpenAI Agents SDK integration helpers.

This module deliberately avoids monkey patching. Applications opt in at each
cross-agent boundary by calling ``auth.call_agent(...)`` or wrapping a tool with
``auth.wrap_tool(...)``.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..agent import AgentInstance
from ..config import MetadataResolverConfig, VerificationConfig, get_runtime_profile
from ..messaging import verify_agent_message
from ..models import (
    AgentRegistryDocument,
    AgentRegistryEntry,
    SignedAgentMessage,
    VerificationFailure,
    VerificationSuccess,
)
from ..remote import RemoteAgentClient
from ..stores import InMemoryNonceStore
from ..verifier import AgentVerifier

RunnerCallable = Callable[[Any, Any], Any | Awaitable[Any]]


class LocalEs256Signer:
    """Small local ES256 signer for tests, demos, and local development."""

    def __init__(self, kid: str) -> None:
        self._kid = kid
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    async def kid(self) -> str:
        return self._kid

    async def algorithm(self) -> str:
        return "ES256"

    async def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def public_key_pem(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )


@dataclass(slots=True, frozen=True)
class OpenAIAgentsAuthConfig:
    roles: tuple[str, ...]
    mode: str = "local"
    domain: str = "127.0.0.1:8700"
    organization: str = "Agent Auth Application"
    environment: str = "local"
    runtime_dir: Path = Path(".agent-auth/runtime")
    registry_url: str | None = None
    registry_publish_url: str | None = None
    registry_client_id: str | None = None
    registry_api_key: str | None = field(default=None, repr=False)
    profile: str = "test"
    capabilities: dict[str, str] = field(default_factory=dict)
    vault_addr: str | None = None
    vault_token_file: str | None = None
    vault_transit_mount: str = "transit"
    vault_namespace: str | None = None
    vault_verify: bool | str = True
    vault_key_names: dict[str, str] = field(default_factory=dict)
    auto_create_vault_keys: bool = True

    @classmethod
    def from_file(cls, path: str | Path) -> OpenAIAgentsAuthConfig:
        config_path = Path(path)
        try:
            import tomllib
        except ModuleNotFoundError as exc:  # pragma: no cover - Python < 3.11 only
            raise RuntimeError("tomllib is required to read agent-auth.toml") from exc

        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        base_dir = config_path.parent
        roles = tuple(str(role).strip() for role in raw.get("roles", []) if str(role).strip())
        if not roles:
            raise ValueError("agent-auth config must define at least one role")

        runtime_dir = Path(_expand(raw.get("runtime_dir", "runtime")))
        if not runtime_dir.is_absolute():
            runtime_dir = base_dir / runtime_dir

        registry = raw.get("registry", {})
        vault = raw.get("vault", {})
        capabilities = {str(k): str(v) for k, v in raw.get("capabilities", {}).items()}
        vault_key_names = {str(k): str(_expand(v)) for k, v in vault.get("key_names", {}).items()}
        vault_token_file = _optional_str(_expand(vault.get("token_file")))
        if vault_token_file is not None:
            token_path = Path(vault_token_file)
            if not token_path.is_absolute():
                token_path = base_dir / token_path
            vault_token_file = str(token_path)
        return cls(
            roles=roles,
            mode=os.getenv("AGENT_AUTH_MODE", str(_expand(raw.get("mode", "local")))).lower(),
            domain=str(_expand(raw.get("domain", "127.0.0.1:8700"))),
            organization=str(_expand(raw.get("organization", "Agent Auth Application"))),
            environment=str(_expand(raw.get("environment", "local"))),
            runtime_dir=runtime_dir,
            registry_url=_optional_str(_expand(registry.get("url"))),
            registry_publish_url=_optional_str(_expand(registry.get("publish_url"))),
            registry_client_id=_optional_str(_expand(registry.get("client_id"))),
            registry_api_key=_optional_str(_expand(registry.get("api_key"))),
            profile=str(_expand(raw.get("profile", "test"))),
            capabilities=capabilities,
            vault_addr=_optional_str(_expand(vault.get("addr"))),
            vault_token_file=vault_token_file,
            vault_transit_mount=str(_expand(vault.get("transit_mount", "transit"))),
            vault_namespace=_optional_str(_expand(vault.get("namespace"))),
            vault_verify=_parse_vault_verify(_expand(vault.get("verify", True))),
            vault_key_names=vault_key_names,
            auto_create_vault_keys=bool(vault.get("auto_create_keys", True)),
        )

    def capability_for(self, role: str) -> str:
        return self.capabilities.get(role, f"agent.{role}")

    def registry_document_url(self) -> str:
        return self.registry_url or f"http://{self.domain}/.well-known/agent.json"


@dataclass(slots=True)
class OpenAIAgentsAuthRuntime:
    config: OpenAIAgentsAuthConfig
    agents: dict[str, AgentInstance] = field(default_factory=dict)
    nonce_stores: dict[str, InMemoryNonceStore] = field(default_factory=dict)

    @classmethod
    async def create(cls, config: OpenAIAgentsAuthConfig) -> OpenAIAgentsAuthRuntime:
        runtime = cls(config=config)
        config.runtime_dir.mkdir(parents=True, exist_ok=True)
        if config.mode == "local":
            runtime._create_local_agents()
            return runtime
        if config.mode == "vault":
            await runtime._create_vault_agents_and_publish()
            return runtime
        raise ValueError("mode must be 'local' or 'vault'")

    def agent(self, role: str) -> AgentInstance:
        try:
            return self.agents[role]
        except KeyError as exc:
            raise KeyError(f"Unknown agent-auth role: {role}") from exc

    async def sign_for_role(
        self,
        source_role: str,
        *,
        payload: Any,
        recipient_role: str,
        message_type: str,
    ) -> SignedAgentMessage:
        return await self.agent(source_role).sign_message(
            payload=_to_payload(payload),
            recipient=self.agent(recipient_role).agent_id,
            message_type=message_type,
        )

    async def verify_for_role(
        self,
        receiver_role: str,
        message: SignedAgentMessage | dict[str, Any],
        *,
        required_sender_capability: str | None = None,
    ) -> VerificationSuccess | VerificationFailure:
        profile = get_runtime_profile(self.config.profile)
        async with self._http_client() as client:
            result = await verify_agent_message(
                message=message,
                nonce_store=self.nonce_stores[receiver_role],
                http_client=client,
                config=VerificationConfig(profile=profile),
                resolver_config=MetadataResolverConfig(
                    profile=profile,
                    registry_url=self.config.registry_document_url(),
                ),
                now=datetime.now(UTC),
                expected_recipient=self.agent(receiver_role).agent_id,
            )
        if not result.ok:
            return result

        if required_sender_capability:
            capabilities = result.metadata.capabilities if result.metadata else []
            if required_sender_capability not in capabilities:
                return VerificationFailure(
                    code="CAPABILITY_DENIED",
                    reason=f"Sender lacks required capability: {required_sender_capability}",
                )
        return result

    def registry_document(self) -> AgentRegistryDocument:
        entries = [
            AgentRegistryEntry(
                agent_id=agent.agent_id,
                metadata=agent.metadata,
                published_at=datetime.now(UTC),
                publisher="agent-auth-local",
            )
            for agent in self.agents.values()
            if agent.metadata is not None
        ]
        return AgentRegistryDocument(updated_at=datetime.now(UTC), agents=entries)

    def _create_local_agents(self) -> None:
        for role in self.config.roles:
            signer = LocalEs256Signer(kid=f"local:{role}")
            agent = AgentInstance.from_signer(
                domain=self.config.domain,
                name=role,
                organization=self.config.organization,
                endpoint=f"http://{self.config.domain}/agents/{role}",
                signer=signer,
                public_key_pem=signer.public_key_pem(),
                kid=f"local:{role}",
                capabilities=["sign", "verify", self.config.capability_for(role)],
                environment=self.config.environment,
            )
            agent.export_metadata(self.config.runtime_dir / "metadata" / role)
            self.agents[role] = agent
            self.nonce_stores[role] = InMemoryNonceStore()

    async def _create_vault_agents_and_publish(self) -> None:
        missing = [
            name
            for name, value in {
                "vault.addr": self.config.vault_addr,
                "vault.token_file": self.config.vault_token_file,
                "registry.publish_url": self.config.registry_publish_url,
                "registry.client_id": self.config.registry_client_id,
                "registry.api_key": self.config.registry_api_key,
            }.items()
            if not value
        ]
        if missing:
            raise RuntimeError("Vault mode requires config values: " + ", ".join(missing))

        async with httpx.AsyncClient() as client:
            for role in self.config.roles:
                key_name = self.config.vault_key_names.get(role, f"agent-auth-{role}")
                agent = await asyncio.to_thread(
                    AgentInstance.from_vault,
                    domain=self.config.domain,
                    name=role,
                    organization=self.config.organization,
                    endpoint=f"https://{self.config.domain}/agents/{role}",
                    vault_addr=self.config.vault_addr or "",
                    vault_token_file=self.config.vault_token_file,
                    transit_mount=self.config.vault_transit_mount,
                    key_name=key_name,
                    namespace=self.config.vault_namespace,
                    verify=self.config.vault_verify,
                    capabilities=["sign", "verify", self.config.capability_for(role)],
                    environment=self.config.environment,
                    auto_create_key=self.config.auto_create_vault_keys,
                )
                agent.export_metadata(self.config.runtime_dir / "metadata" / role)
                await agent.publish(
                    registry_url=self.config.registry_publish_url or "",
                    client_id=self.config.registry_client_id or "",
                    api_key=self.config.registry_api_key or "",
                    http_client=client,
                )
                self.agents[role] = agent
                self.nonce_stores[role] = InMemoryNonceStore()

    def _http_client(self) -> httpx.AsyncClient:
        if self.config.mode == "local":
            return httpx.AsyncClient(transport=self._registry_transport())
        return httpx.AsyncClient()

    def _registry_transport(self) -> httpx.MockTransport:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/.well-known/agent.json":
                payload = json.loads(self.registry_document().model_dump_json())
                return httpx.Response(200, json=payload)
            return httpx.Response(404, json={"error": "not found"})

        return httpx.MockTransport(handler)


@dataclass(slots=True)
class AuthenticatedOpenAIAgents:
    """兼容的 multi-role 适配器。

    .. deprecated:: 0.2.0b1
       新项目使用 :class:`OpenAIAgentAuth`。该类至少保留一个 beta 发布周期。
    """

    runtime: OpenAIAgentsAuthRuntime
    enabled: bool | None = None
    _trusted_events: list[str] = field(default_factory=list)

    @classmethod
    async def from_config(cls, config: OpenAIAgentsAuthConfig) -> AuthenticatedOpenAIAgents:
        return cls(runtime=await OpenAIAgentsAuthRuntime.create(config))

    @classmethod
    async def from_config_file(cls, path: str | Path) -> AuthenticatedOpenAIAgents:
        return await cls.from_config(OpenAIAgentsAuthConfig.from_file(path))

    def is_enabled(self) -> bool:
        if self.enabled is not None:
            enabled = self.enabled
        else:
            enabled = os.getenv("AGENT_AUTH_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
        if not enabled and self.runtime.config.profile == "strict":
            raise RuntimeError("AGENT_AUTH_ENABLED cannot disable authentication in strict profile")
        return enabled

    async def call_local_agent(
        self,
        *,
        source_role: str,
        target_role: str,
        target_agent: Any,
        payload: Any,
        runner: RunnerCallable,
        message_type: str = "agent.call",
    ) -> Any:
        if not self.is_enabled():
            return await _maybe_await(runner(target_agent, _runner_input(runner, payload)))

        signed_request = await self.runtime.sign_for_role(
            source_role,
            payload=payload,
            recipient_role=target_role,
            message_type=f"{message_type}.request",
        )
        verified_request = _require_verified(
            await self.runtime.verify_for_role(
                target_role,
                signed_request,
                required_sender_capability=self.runtime.config.capability_for(source_role),
            )
        )
        assert verified_request.message is not None

        raw_result = await _maybe_await(runner(target_agent, _runner_input(runner, verified_request.message.payload)))
        result_payload = _to_payload(raw_result)
        signed_result = await self.runtime.sign_for_role(
            target_role,
            payload=result_payload,
            recipient_role=source_role,
            message_type=f"{message_type}.result",
        )
        verified_result = _require_verified(
            await self.runtime.verify_for_role(
                source_role,
                signed_result,
                required_sender_capability=self.runtime.config.capability_for(target_role),
            )
        )
        assert verified_result.message is not None

        self._trusted_events.append(f"{source_role} -> {target_role} -> {source_role} verified")
        return verified_result.message.payload

    async def call_agent(self, **kwargs: Any) -> Any:
        """兼容入口；同进程调用请优先使用 call_local_agent()。"""

        return await self.call_local_agent(**kwargs)

    async def call_remote_agent(
        self,
        *,
        source_role: str,
        target_agent_id: str,
        target_url: str,
        payload: Any,
        message_type: str = "agent.call.result",
    ) -> Any:
        """在真实 HTTP 边界发送签名请求并验证目标 Agent 的签名响应。"""

        profile = get_runtime_profile(self.runtime.config.profile)
        async with self.runtime._http_client() as client:
            verifier = AgentVerifier(
                nonce_store=self.runtime.nonce_stores[source_role],
                verification_config=VerificationConfig(profile=profile),
                resolver_config=MetadataResolverConfig(
                    profile=profile,
                    registry_url=self.runtime.config.registry_document_url(),
                ),
                http_client=client,
            )
            remote = RemoteAgentClient(
                sender=self.runtime.agent(source_role),
                verifier=verifier,
                http_client=client,
            )
            result = await remote.call(
                target_url=target_url,
                target_agent_id=target_agent_id,
                payload=_to_payload(payload),
                message_type=message_type,
            )
        self._trusted_events.append(f"{source_role} -> {target_agent_id} remote verified")
        return result

    async def sign_remote_result(
        self,
        *,
        target_role: str,
        recipient_agent_id: str,
        payload: Any,
        message_type: str = "agent.call.result",
    ) -> SignedAgentMessage:
        return await self.runtime.agent(target_role).sign_message(
            payload=_to_payload(payload),
            recipient=recipient_agent_id,
            message_type=message_type,
        )

    async def call_tool(self, **kwargs: Any) -> Any:
        return await self.call_local_agent(**kwargs)

    def wrap_tool(
        self,
        *,
        source_role: str,
        target_role: str,
        target_agent: Any,
        runner: RunnerCallable,
        message_type: str = "agent.call",
    ) -> Callable[[Any], Awaitable[Any]]:
        async def wrapped(payload: Any) -> Any:
            return await self.call_local_agent(
                source_role=source_role,
                target_role=target_role,
                target_agent=target_agent,
                payload=payload,
                runner=runner,
                message_type=message_type,
            )

        return wrapped

    def wrap_remote_tool(
        self,
        *,
        source_role: str,
        target_agent_id: str,
        target_url: str,
        message_type: str = "agent.call.result",
    ) -> Callable[[Any], Awaitable[Any]]:
        """返回可直接交给 function_tool 的远程认证 callable。"""

        async def wrapped(payload: Any) -> Any:
            return await self.call_remote_agent(
                source_role=source_role,
                target_agent_id=target_agent_id,
                target_url=target_url,
                payload=payload,
                message_type=message_type,
            )

        return wrapped

    def maybe_authenticate_tools(
        self,
        *,
        source_role: str,
        specialists: dict[str, Any],
        fallback_tools: dict[str, Any],
        runner: RunnerCallable,
        role_map: dict[str, str] | None = None,
        message_type: str = "agent.call",
    ) -> dict[str, Callable[[Any], Awaitable[Any]]]:
        if not self.is_enabled():
            return fallback_tools

        mapped: dict[str, Callable[[Any], Awaitable[Any]]] = {}
        for tool_name in fallback_tools:
            target_role = (role_map or {}).get(tool_name, tool_name)
            if target_role not in specialists:
                mapped[tool_name] = fallback_tools[tool_name]
                continue
            mapped[tool_name] = self.wrap_tool(
                source_role=source_role,
                target_role=target_role,
                target_agent=specialists[target_role],
                runner=runner,
                message_type=message_type,
            )
        return mapped

    def trusted_events(self) -> list[str]:
        return list(self._trusted_events)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _require_verified(result: VerificationSuccess | VerificationFailure) -> VerificationSuccess:
    if isinstance(result, VerificationFailure):
        raise PermissionError(f"{result.code}: {result.reason}")
    if result.message is None:
        raise PermissionError("Verification succeeded without a signed message")
    return result


def _to_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "final_output"):
        return _to_payload(value.final_output)
    return value


def _runner_input(runner: RunnerCallable, payload: Any) -> Any:
    """真实 OpenAI Runner 仅接受 str/Response input；本地 fake runner 保持原值。"""

    runner_module = getattr(runner, "__module__", "")
    if runner_module.startswith("agents."):
        if isinstance(payload, str):
            return payload
        return json.dumps(_to_payload(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return payload


def _expand(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    expanded = os.path.expandvars(value)
    if expanded.startswith("${") and expanded.endswith("}"):
        return ""
    return expanded


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _parse_vault_verify(value: Any) -> bool | str:
    if isinstance(value, bool):
        return value
    text = str(value).strip()
    if text.lower() in {"0", "false", "no", "off"}:
        return False
    if text.lower() in {"1", "true", "yes", "on"}:
        return True
    return text
