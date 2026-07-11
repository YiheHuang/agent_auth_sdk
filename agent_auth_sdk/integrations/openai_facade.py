"""面向已有 OpenAI Agents 项目的高层认证入口。"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

import httpx
from pydantic import TypeAdapter, ValidationError

from agent_auth_sdk.agent import AgentInstance
from agent_auth_sdk.auth_context import AuthenticatedAgentContext
from agent_auth_sdk.config import MetadataResolverConfig, VerificationConfig, get_runtime_profile
from agent_auth_sdk.errors import (
    AgentAuthenticationError,
    AgentAuthError,
    AgentAuthorizationError,
    AgentConfigurationError,
    AgentDiscoveryError,
    AgentReplayError,
    AgentTransportError,
    VerificationErrorCode,
)
from agent_auth_sdk.models import VerificationFailure, VerificationSuccess
from agent_auth_sdk.observability import AgentAuthEvent, EventSink, emit_event
from agent_auth_sdk.registry_client import RegistryClient
from agent_auth_sdk.remote import RemoteAgentClient
from agent_auth_sdk.verifier import AgentVerifier, AuthorizationPolicy

from .openai_agents import LocalEs256Signer, OpenAIAgentsAuthConfig, OpenAIAgentsAuthRuntime, _to_payload

T = TypeVar("T")


@runtime_checkable
class AuthenticatedTool(Protocol):
    """OpenAI 之外的框架也可实现的最小工具协议。"""

    name: str
    description: str
    params_json_schema: dict[str, Any]


@dataclass(slots=True, frozen=True)
class RemoteAgentToolSpec:
    """批量声明远程 Agent tool 的不可变配置。"""

    name: str
    target: str
    url: str
    input_type: type[Any]
    output_type: type[Any] | None = None
    description: str | None = None
    is_enabled: Any = True
    message_type: str = "agent.call.result"


@dataclass(slots=True)
class OpenAIAgentAuth:
    """一个应用进程所拥有的单个可签名 Agent 身份。

    local profile 可以附带多 role 的内存 runtime，用于同进程 Tool/Handoff
    契约测试；strict/vault 运行只加载 ``identity`` 对应的 signer。
    """

    identity: str
    agent: AgentInstance
    verifier: AgentVerifier
    profile: str
    registry_client: RegistryClient | None = None
    authorization_policy: AuthorizationPolicy | None = None
    event_sink: EventSink | None = None
    enabled: bool = True
    _http_client: httpx.AsyncClient | None = None
    _owns_http_client: bool = False
    _local_runtime: OpenAIAgentsAuthRuntime | None = None
    _bindings: dict[int, str] = field(default_factory=dict)
    _binding_objects: dict[int, Any] = field(default_factory=dict)
    _events: list[AgentAuthEvent] = field(default_factory=list)

    @classmethod
    async def from_env(
        cls,
        *,
        identity: str,
        config_path: str | Path = ".agent-auth/agent-auth.toml",
        authorization_policy: AuthorizationPolicy | None = None,
        event_sink: EventSink | None = None,
    ) -> OpenAIAgentAuth:
        """从 TOML 与环境变量加载运行身份；不会创建 key 或发布 metadata。"""

        return await cls.from_config(
            OpenAIAgentsAuthConfig.from_file(config_path),
            identity=identity,
            authorization_policy=authorization_policy,
            event_sink=event_sink,
            provision=False,
        )

    @classmethod
    def from_env_sync(cls, **kwargs: Any) -> OpenAIAgentAuth:
        return cast(OpenAIAgentAuth, _run_sync(cls.from_env(**kwargs)))

    @classmethod
    async def from_config(
        cls,
        config: OpenAIAgentsAuthConfig,
        *,
        identity: str,
        authorization_policy: AuthorizationPolicy | None = None,
        event_sink: EventSink | None = None,
        provision: bool = False,
    ) -> OpenAIAgentAuth:
        role = _role_for_identity(config, identity)
        profile = get_runtime_profile(config.profile)
        enabled = os.getenv("AGENT_AUTH_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
        if not enabled and profile.name == "strict":
            raise AgentConfigurationError("AGENT_AUTH_ENABLED cannot disable authentication in strict profile")

        client = httpx.AsyncClient(follow_redirects=False)
        resolver_config = MetadataResolverConfig(profile=profile, registry_url=config.registry_document_url())
        verifier = AgentVerifier(
            verification_config=VerificationConfig(profile=profile),
            resolver_config=resolver_config,
            http_client=client,
            event_sink=event_sink,
        )
        registry_client = _registry_client(config, client)

        if config.mode == "local":
            runtime = await OpenAIAgentsAuthRuntime.create(config)
            instance = runtime.agent(role)
            return cls(
                identity=role,
                agent=instance,
                verifier=verifier,
                profile=profile.name,
                registry_client=registry_client,
                authorization_policy=authorization_policy,
                event_sink=event_sink,
                enabled=enabled,
                _http_client=client,
                _owns_http_client=True,
                _local_runtime=runtime,
            )
        if config.mode != "vault":
            await client.aclose()
            raise AgentConfigurationError("mode must be 'local' or 'vault'")

        missing = [
            name
            for name, value in {
                "vault.addr": config.vault_addr,
                "vault.token_file": config.vault_token_file,
                "vault.key_names.<identity>": config.vault_key_names.get(role),
            }.items()
            if not value
        ]
        if missing:
            await client.aclose()
            raise AgentConfigurationError("Vault identity requires: " + ", ".join(missing))
        try:
            instance = await asyncio.to_thread(
                AgentInstance.from_vault,
                domain=config.domain,
                name=role,
                organization=config.organization,
                endpoint=f"https://{config.domain}/agents/{role}",
                vault_addr=config.vault_addr or "",
                vault_token_file=config.vault_token_file,
                transit_mount=config.vault_transit_mount,
                key_name=config.vault_key_names[role],
                namespace=config.vault_namespace,
                verify=config.vault_verify,
                capabilities=["sign", "verify", config.capability_for(role)],
                environment=config.environment,
                auto_create_key=provision and config.auto_create_vault_keys,
            )
        except Exception as exc:
            await client.aclose()
            raise AgentConfigurationError(
                "Unable to load the configured Vault identity",
                agent_id=identity if identity.startswith("agent://") else None,
            ) from exc
        auth = cls(
            identity=role,
            agent=instance,
            verifier=verifier,
            profile=profile.name,
            registry_client=registry_client,
            authorization_policy=authorization_policy,
            event_sink=event_sink,
            enabled=enabled,
            _http_client=client,
            _owns_http_client=True,
        )
        if provision:
            await auth.provision()
        return auth

    @classmethod
    def from_components(
        cls,
        *,
        identity: str,
        agent: AgentInstance,
        verifier: AgentVerifier,
        profile: str = "strict",
        registry_client: RegistryClient | None = None,
        authorization_policy: AuthorizationPolicy | None = None,
        event_sink: EventSink | None = None,
    ) -> OpenAIAgentAuth:
        return cls(
            identity=identity,
            agent=agent,
            verifier=verifier,
            profile=profile,
            registry_client=registry_client,
            authorization_policy=authorization_policy,
            event_sink=event_sink,
        )

    @classmethod
    def local(cls, *, identity: str, domain: str = "127.0.0.1:8700") -> OpenAIAgentAuth:
        """无需外部服务的单身份构造器；只用于开发和测试。"""

        signer = LocalEs256Signer(kid=f"local:{identity}")
        instance = AgentInstance.from_signer(
            domain=domain,
            name=identity,
            organization="Agent Auth local development",
            endpoint=f"http://{domain}/agents/{identity}",
            signer=signer,
            public_key_pem=signer.public_key_pem(),
            kid=f"local:{identity}",
            capabilities=["sign", "verify", f"agent.{identity}"],
            environment="local",
        )
        return cls(identity=identity, agent=instance, verifier=AgentVerifier(), profile="test")

    async def __aenter__(self) -> OpenAIAgentAuth:
        await self.verifier.__aenter__()
        if self.registry_client is not None:
            await self.registry_client.__aenter__()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self.registry_client is not None:
            await self.registry_client.__aexit__()
        await self.verifier.__aexit__()
        if self._owns_http_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def provision(self) -> dict[str, Any]:
        """显式发布当前身份；运行时加载不会隐式调用它。"""

        if self.registry_client is None:
            raise AgentConfigurationError("Registry publish credentials are not configured")
        if self.agent.metadata is None:
            raise AgentConfigurationError("Agent metadata is not initialized")
        return cast(dict[str, Any], await self.registry_client.publish(self.agent.metadata, signer=self.agent.signer))

    def provision_sync(self) -> dict[str, Any]:
        return cast(dict[str, Any], _run_sync(self.provision()))

    def bind(
        self,
        bindings: Mapping[str, Any] | Mapping[Any, str] | Iterable[tuple[Any, str]],
    ) -> OpenAIAgentAuth:
        """将 OpenAI ``Agent`` 对象与 role 绑定，并拒绝歧义绑定。

        OpenAI ``Agent`` 是不可哈希 dataclass，推荐使用 ``{role: agent}``；
        iterable ``[(agent, role)]`` 用于工厂或动态绑定。
        """

        known_roles = set(self._local_runtime.agents) if self._local_runtime is not None else {self.identity}
        used_roles = set(self._bindings.values())
        raw_items = bindings.items() if isinstance(bindings, Mapping) else bindings
        for left, right in raw_items:
            if isinstance(left, str) and not isinstance(right, str):
                role, agent_object = left, right
            else:
                agent_object, role = left, right
            if not isinstance(role, str):
                raise AgentConfigurationError("bind() expects {role: agent} or [(agent, role)]")
            if role not in known_roles:
                raise AgentConfigurationError(f"Unknown configured role: {role}")
            object_id = id(agent_object)
            existing = self._bindings.get(object_id)
            if existing is not None and existing != role:
                raise AgentConfigurationError(f"Agent object is already bound to role: {existing}")
            if role in used_roles and existing != role:
                raise AgentConfigurationError(f"Role is already bound to a different Agent object: {role}")
            self._bindings[object_id] = role
            self._binding_objects[object_id] = agent_object
            used_roles.add(role)
        return self

    def role_for(self, agent_object: Any) -> str:
        try:
            return self._bindings[id(agent_object)]
        except KeyError as exc:
            raise AgentConfigurationError("Agent object has not been bound; call auth.bind({...}) first") from exc

    def protect_tool(self, tool: T, *, target: str) -> T:
        """原样保留 ``FunctionTool`` 元数据，只包装其执行边界。"""

        if not hasattr(tool, "on_invoke_tool") or not hasattr(tool, "params_json_schema"):
            raise AgentConfigurationError("protect_tool() requires an OpenAI Agents FunctionTool")
        target_role = self._local_target_role(target)
        original = cast(Any, tool).on_invoke_tool

        async def invoke(context: Any, arguments_json: str) -> Any:
            try:
                payload = json.loads(arguments_json)
            except json.JSONDecodeError as exc:
                raise AgentAuthenticationError("Tool arguments are not valid JSON", code="TOOL_INPUT_INVALID") from exc

            async def operation() -> Any:
                return await original(context, arguments_json)

            return await self._local_exchange(
                target_role=target_role,
                payload=payload,
                operation=operation,
                operation_name="openai.function_tool",
            )

        return cast(T, replace(cast(Any, tool), on_invoke_tool=invoke))

    def agent_as_tool(
        self,
        target_agent: Any,
        *,
        identity: str | None = None,
        tool_name: str | None = None,
        tool_description: str | None = None,
        custom_output_extractor: Callable[[Any], Any] | None = None,
        is_enabled: Any = True,
    ) -> Any:
        """创建并认证 OpenAI ``Agent.as_tool()``，无需手写 ``Runner.run``。"""

        target = identity or self.role_for(target_agent)
        as_tool_kwargs: dict[str, Any] = {
            "tool_name": tool_name,
            "tool_description": tool_description,
            "custom_output_extractor": custom_output_extractor,
        }
        if "is_enabled" in inspect.signature(target_agent.as_tool).parameters:
            as_tool_kwargs["is_enabled"] = is_enabled
        tool = target_agent.as_tool(**as_tool_kwargs)
        if "is_enabled" not in as_tool_kwargs and hasattr(tool, "is_enabled"):
            tool = replace(tool, is_enabled=is_enabled)
        return self.protect_tool(tool, target=target)

    def remote_agent_tool(
        self,
        *,
        name: str,
        target: str,
        url: str,
        input_type: type[Any],
        output_type: type[Any] | None = None,
        description: str | None = None,
        is_enabled: Any = True,
        message_type: str = "agent.call.result",
    ) -> Any:
        """返回可直接放入 ``Agent.tools`` 的签名远程 ``FunctionTool``。"""

        try:
            from agents import FunctionTool
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise AgentConfigurationError("Install verifiable-agent-auth-sdk[openai]") from exc
        input_adapter = TypeAdapter(input_type)
        output_adapter = TypeAdapter(output_type) if output_type is not None else None

        async def invoke(_: Any, arguments_json: str) -> Any:
            started = time.perf_counter()
            try:
                request_value = input_adapter.validate_json(arguments_json)
                payload = input_adapter.dump_python(request_value, mode="json")
                remote = RemoteAgentClient(sender=self.agent, verifier=self.verifier, http_client=self._http_client)
                result = await remote.call(
                    target_url=url,
                    target_agent_id=target,
                    payload=payload,
                    message_type=message_type,
                )
                validated = output_adapter.validate_python(result) if output_adapter is not None else result
                await self._record("openai.remote_tool", target, True, started)
                return validated
            except ValidationError as exc:
                await self._record("openai.remote_tool", target, False, started, code="TOOL_SCHEMA_INVALID")
                raise AgentAuthenticationError(
                    "Remote tool input or output did not match its schema", code="TOOL_SCHEMA_INVALID"
                ) from exc
            except AgentAuthError as exc:
                await self._record("openai.remote_tool", target, False, started, code=exc.code)
                raise
            except httpx.HTTPError as exc:
                await self._record("openai.remote_tool", target, False, started, code="TRANSPORT_FAILED")
                raise AgentTransportError("Remote Agent request failed", agent_id=target) from exc
            except PermissionError as exc:
                error = _permission_error(exc, target)
                await self._record("openai.remote_tool", target, False, started, code=error.code)
                raise error from exc

        return FunctionTool(
            name=name,
            description=description or f"Call authenticated Agent {target}.",
            params_json_schema=input_adapter.json_schema(),
            on_invoke_tool=invoke,
            strict_json_schema=True,
            is_enabled=is_enabled,
        )

    def remote_agent_tools(self, specs: Iterable[RemoteAgentToolSpec]) -> list[Any]:
        """从配置批量创建远程 Agent tools，保持输入顺序。"""

        return [
            self.remote_agent_tool(
                name=spec.name,
                target=spec.target,
                url=spec.url,
                input_type=spec.input_type,
                output_type=spec.output_type,
                description=spec.description,
                is_enabled=spec.is_enabled,
                message_type=spec.message_type,
            )
            for spec in specs
        ]

    def authenticated_handoff(
        self,
        target_agent: Any,
        *,
        identity: str | None = None,
        tool_name: str | None = None,
        tool_description: str | None = None,
        input_type: type[Any] | None = None,
        input_filter: Any = None,
        is_enabled: Any = True,
    ) -> Any:
        """认证同进程 handoff；它提供审计与授权，不提供进程隔离。"""

        try:
            from agents import handoff
        except ImportError as exc:  # pragma: no cover
            raise AgentConfigurationError("Install verifiable-agent-auth-sdk[openai]") from exc
        target = identity or self.role_for(target_agent)
        target_role = self._local_target_role(target)
        handoff_kwargs: dict[str, Any] = {
            "agent": target_agent,
            "tool_name_override": tool_name,
            "tool_description_override": tool_description,
            "input_filter": input_filter,
            "is_enabled": is_enabled,
        }
        if input_type is not None:
            handoff_kwargs["input_type"] = input_type
            handoff_kwargs["on_handoff"] = lambda *_: None
        base = handoff(**handoff_kwargs)
        original = base.on_invoke_handoff

        async def invoke(context: Any, arguments_json: str) -> Any:
            async def operation() -> Any:
                return await original(context, arguments_json)

            return await self._local_exchange(
                target_role=target_role,
                payload={"handoff": json.loads(arguments_json or "{}")},
                operation=operation,
                operation_name="openai.handoff",
                signed_result={"handoff": "accepted"},
            )

        return replace(base, on_invoke_handoff=invoke)

    def authenticated_context(self, result: VerificationSuccess) -> AuthenticatedAgentContext:
        capabilities = tuple(result.metadata.capabilities) if result.metadata is not None else ()
        return AuthenticatedAgentContext(
            agent_id=result.agent_id,
            kid=result.kid,
            capabilities=capabilities,
            request_id=result.request_id,
        )

    def events(self) -> list[AgentAuthEvent]:
        return list(self._events)

    async def _local_exchange(
        self,
        *,
        target_role: str,
        payload: Any,
        operation: Callable[[], Any],
        operation_name: str,
        signed_result: Any | None = None,
    ) -> Any:
        if not self.enabled:
            value = operation()
            return await value if hasattr(value, "__await__") else value
        runtime = self._local_runtime
        if runtime is None:
            raise AgentConfigurationError(
                "Local Tool/Handoff protection requires local multi-role mode; use remote_agent_tool() in production"
            )
        started = time.perf_counter()
        try:
            request = await runtime.sign_for_role(
                self.identity,
                payload=payload,
                recipient_role=target_role,
                message_type=f"{operation_name}.request",
            )
            verified = await runtime.verify_for_role(target_role, request)
            _raise_verification(verified, runtime.agent(target_role).agent_id)
            value = operation()
            raw_result = await value if hasattr(value, "__await__") else value
            result_payload = signed_result if signed_result is not None else _to_payload(raw_result)
            response = await runtime.sign_for_role(
                target_role,
                payload=result_payload,
                recipient_role=self.identity,
                message_type=f"{operation_name}.result",
            )
            verified_response = await runtime.verify_for_role(self.identity, response)
            _raise_verification(verified_response, self.agent.agent_id)
            await self._record(operation_name, runtime.agent(target_role).agent_id, True, started)
            return raw_result
        except AgentAuthError as exc:
            await self._record(operation_name, runtime.agent(target_role).agent_id, False, started, code=exc.code)
            raise

    def _local_target_role(self, target: str) -> str:
        runtime = self._local_runtime
        if runtime is None:
            raise AgentConfigurationError(
                "Local Tool/Handoff protection requires local multi-role mode; use remote_agent_tool() in production"
            )
        if target in runtime.agents:
            return target
        for role, instance in runtime.agents.items():
            if instance.agent_id == target:
                return role
        raise AgentConfigurationError(f"Target is not a configured local role or Agent ID: {target}")

    async def _record(
        self,
        operation: str,
        target_agent_id: str | None,
        ok: bool,
        started: float,
        *,
        code: str = "OK",
        request_id: str | None = None,
    ) -> None:
        event = AgentAuthEvent(
            operation=operation,
            source_agent_id=self.agent.agent_id,
            target_agent_id=target_agent_id,
            ok=ok,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            code=code,
            request_id=request_id,
        )
        self._events.append(event)
        await emit_event(self.event_sink, event)


def _role_for_identity(config: OpenAIAgentsAuthConfig, identity: str) -> str:
    if identity in config.roles:
        return identity
    for role in config.roles:
        expected = f"agent://{config.domain}/{role}"
        if identity == expected:
            return role
    raise AgentConfigurationError(f"Identity is not declared in config roles: {identity}")


def _registry_client(config: OpenAIAgentsAuthConfig, client: httpx.AsyncClient) -> RegistryClient | None:
    if not (config.registry_publish_url and config.registry_client_id and config.registry_api_key):
        return None
    base_url = config.registry_publish_url
    suffix = "/v1/agents/publish"
    if base_url.endswith(suffix):
        base_url = base_url[: -len(suffix)]
    return RegistryClient(
        base_url=base_url,
        client_id=config.registry_client_id,
        api_key=config.registry_api_key,
        http_client=client,
        allow_insecure_http=config.profile == "test",
    )


def _raise_verification(result: VerificationSuccess | VerificationFailure, agent_id: str | None = None) -> None:
    if isinstance(result, VerificationSuccess):
        return
    if result.code == VerificationErrorCode.NONCE_REPLAYED.value:
        raise AgentReplayError(result.reason, code=result.code, agent_id=agent_id)
    if result.code in {VerificationErrorCode.METADATA_FETCH_FAILED.value, VerificationErrorCode.INVALID_METADATA.value}:
        raise AgentDiscoveryError(result.reason, code=result.code, agent_id=agent_id)
    if result.code == VerificationErrorCode.POLICY_REJECTED.value:
        raise AgentAuthorizationError(result.reason, code=result.code, agent_id=agent_id)
    raise AgentAuthenticationError(result.reason, code=result.code, agent_id=agent_id)


def _permission_error(exc: PermissionError, agent_id: str) -> AgentAuthError:
    message = str(exc)
    code = message.split(":", 1)[0] if ":" in message else "AUTHENTICATION_FAILED"
    if code == VerificationErrorCode.NONCE_REPLAYED.value:
        return AgentReplayError("Remote Agent response was replayed", agent_id=agent_id)
    if code in {VerificationErrorCode.METADATA_FETCH_FAILED.value, VerificationErrorCode.INVALID_METADATA.value}:
        return AgentDiscoveryError("Remote Agent metadata could not be resolved", code=code, agent_id=agent_id)
    return AgentAuthenticationError("Remote Agent response authentication failed", code=code, agent_id=agent_id)


def _run_sync(awaitable: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    raise AgentConfigurationError("Synchronous Agent Auth entry points cannot run inside an active event loop")
