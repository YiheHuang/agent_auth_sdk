"""唯一 AgentAuth facade。"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from ._config import Settings
from ._errors import AgentAuthError
from ._identity import resolve_public_host
from ._protocol import DevSigner, SignedEnvelope, Signer, sign_envelope, verify_envelope
from ._registry import Registry
from ._state import MemoryNonceState, SQLiteNonceState
from ._types import AgentRecord
from ._vault import VaultSigner


class AgentAuth:
    """配置、身份、OpenAI Runner 与远程 endpoint 的唯一公开入口。"""

    def __init__(self, config: str | Path | None = None) -> None:
        self._settings = Settings.load(config)
        self._bindings: dict[int, str] = {}
        self._objects: dict[str, Any] = {}
        self._signers: dict[str, Signer] = {}
        self._vault_signers: list[VaultSigner] = []
        self._nonce_state = (
            MemoryNonceState() if self._settings.mode == "dev" else SQLiteNonceState(self._settings.state)
        )
        self._registry = Registry(
            self._settings.registry,
            strict=self._settings.strict,
            client_id=self._settings.client_id,
        )
        self._http = httpx.AsyncClient(timeout=30, follow_redirects=False)
        self._started = False
        self._wrapped_tools: dict[int, Any] = {}
        self._wrapped_handoffs: dict[int, Any] = {}
        self._auth_tool_ids: set[int] = set()
        self._instrument_lock = asyncio.Lock()
        self._server: Any | None = None

    def bind(self, mapping: Mapping[str, Any]) -> AgentAuth:
        """将配置 alias 绑定到 OpenAI Agent 对象。"""

        for alias, agent in mapping.items():
            if alias not in self._settings.agents:
                raise AgentAuthError("IDENTITY_NOT_CONFIGURED", f"Unknown identity alias: {alias}")
            object_id = id(agent)
            existing = self._bindings.get(object_id)
            if existing and existing != alias:
                raise AgentAuthError("AGENT_ALREADY_BOUND", "OpenAI Agent is already bound to another identity")
            if alias in self._objects and self._objects[alias] is not agent:
                raise AgentAuthError("IDENTITY_ALREADY_BOUND", f"Identity {alias} is already bound")
            self._bindings[object_id] = alias
            self._objects[alias] = agent
        return self

    async def _start(self) -> AgentAuth:
        if self._started:
            return self
        if self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=30, follow_redirects=False)
        await self._registry.start()
        try:
            for alias, identity in self._settings.agents.items():
                if not self._settings.uses_vault:
                    signer: Signer = DevSigner(identity.agent_id)
                else:
                    if self._settings.vault is None:  # pragma: no cover - config enforces this
                        raise AgentAuthError("VAULT_CONFIG_INVALID", "Vault is required in production")
                    vault_signer = VaultSigner(
                        agent_id=identity.agent_id,
                        settings=self._settings.vault,
                        identity=identity,
                    )
                    await vault_signer.start()
                    self._vault_signers.append(vault_signer)
                    signer = vault_signer
                self._signers[alias] = signer
                if not self._settings.uses_vault:
                    self._registry.add_dev_record(
                        AgentRecord(
                            agent_id=identity.agent_id,
                            endpoint=identity.endpoint,
                            capabilities=identity.capabilities,
                            kid=signer.kid,
                            public_key=signer.public_key,
                            updated_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                        )
                    )
        except Exception:
            await self.close()
            raise
        self._started = True
        return self

    async def close(self) -> None:
        for signer in self._vault_signers:
            await signer.close()
        self._vault_signers.clear()
        await self._registry.close()
        await self._http.aclose()
        self._started = False

    async def __aenter__(self) -> AgentAuth:
        return await self._start()

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def __enter__(self) -> AgentAuth:
        # Async clients are bound to the loop that uses them.  A synchronous
        # context therefore defers startup to ``run_sync`` instead of creating
        # clients in a short-lived loop here.
        return self

    def __exit__(self, *_: object) -> None:
        asyncio.run(self.close())

    async def run(self, starting_agent: Any, input: Any, **kwargs: Any) -> Any:
        """认证边界后委托给 OpenAI ``Runner.run``。"""

        await self._start()
        await self._instrument()
        self._require_bound(starting_agent)
        Runner = _openai_runner()
        return await Runner.run(starting_agent, input, **kwargs)

    def run_sync(self, starting_agent: Any, input: Any, **kwargs: Any) -> Any:
        """同步入口；活跃 event loop 中必须使用 ``await run``。"""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            was_started = self._started

            async def execute() -> Any:
                try:
                    return await self.run(starting_agent, input, **kwargs)
                finally:
                    if not was_started:
                        await self.close()

            return asyncio.run(execute())
        raise AgentAuthError("SYNC_IN_ASYNC_CONTEXT", "run_sync cannot be used inside an active event loop")

    def run_streamed(self, starting_agent: Any, input: Any, **kwargs: Any) -> Any:
        """返回 OpenAI 原生 ``RunResultStreaming``；跨 Agent 事件仍逐次认证。"""

        if not self._started:
            raise AgentAuthError("AUTH_NOT_STARTED", "Use AgentAuth as a context manager before run_streamed")
        self._instrument_sync()
        self._require_bound(starting_agent)
        Runner = _openai_runner()
        return Runner.run_streamed(starting_agent, input, **kwargs)

    async def call(self, source: str, target: str, payload: Any) -> Any:
        """Call an authenticated Agent endpoint without depending on an Agent framework."""

        if source not in self._settings.agents:
            raise AgentAuthError("IDENTITY_NOT_CONFIGURED", f"Unknown source identity alias: {source}")
        if target in self._settings.agents:
            target_id = self._settings.agents[target].agent_id
        else:
            try:
                target_id = self._settings.remotes[target]
            except KeyError as exc:
                raise AgentAuthError("REMOTE_NOT_CONFIGURED", f"Unknown target identity alias: {target}") from exc
        await self._start()
        return await self._remote_call(source, target_id, _strict_json_value(payload))

    def remote_tool(
        self,
        alias: str,
        *,
        input_type: type[Any],
        output_type: type[Any],
        name: str | None = None,
        description: str | None = None,
    ) -> Any:
        """创建一个会自动签名请求并验证响应的 OpenAI FunctionTool。"""

        try:
            target_id = self._settings.remotes[alias]
        except KeyError as exc:
            raise AgentAuthError("REMOTE_NOT_CONFIGURED", f"Unknown remote alias: {alias}") from exc
        FunctionTool, TypeAdapter = _openai_tool_types()
        input_adapter = TypeAdapter(input_type)
        output_adapter = TypeAdapter(output_type)

        async def invoke(context: Any, arguments: str) -> Any:
            await self._start()
            source_alias = self._alias_for(getattr(context, "agent", None))
            try:
                payload = input_adapter.validate_json(arguments)
            except (TypeError, ValueError) as exc:
                raise AgentAuthError("SCHEMA_INVALID", "Remote Agent input does not match the declared schema") from exc
            payload_value = _json_value(payload)
            result_payload = await self._remote_call(source_alias, target_id, payload_value)
            try:
                return output_adapter.validate_python(result_payload)
            except (TypeError, ValueError) as exc:
                raise AgentAuthError(
                    "SCHEMA_INVALID", "Remote Agent output does not match the declared schema"
                ) from exc

        tool = FunctionTool(
            name=name or alias,
            description=description or f"Call the authenticated {alias} Agent.",
            params_json_schema=input_adapter.json_schema(),
            on_invoke_tool=invoke,
            strict_json_schema=True,
        )
        self._auth_tool_ids.add(id(tool))
        return tool

    async def _remote_call(self, source_alias: str, target_id: str, payload: Any) -> Any:
        source = self._settings.agents[source_alias]
        target = await self._registry.resolve(target_id)
        endpoint = target.endpoint
        headers = {"Content-Type": "application/agent-auth+json"}
        extensions: dict[str, Any] | None = None
        if self._settings.strict:
            endpoint, host_header, sni_hostname = _pin_public_endpoint(endpoint)
            headers["Host"] = host_header
            extensions = {"sni_hostname": sni_hostname}
        request = await sign_envelope(
            sender=source.agent_id,
            audience=target_id,
            call_type="agent.call",
            payload=payload,
            signer=self._signers[source_alias],
        )
        try:
            response = await self._http.post(
                endpoint,
                json=request.as_dict(),
                headers={**headers, "X-Request-ID": request.id},
                extensions=extensions,
            )
            if response.status_code >= 400:
                raise _remote_error(response, request.id)
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            reply = SignedEnvelope.from_dict(value)
        except AgentAuthError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise AgentAuthError("REMOTE_CALL_FAILED", "Remote Agent call failed", request_id=request.id) from exc
        record = await self._registry.resolve(target_id)
        _, result_payload = verify_envelope(
            reply,
            record=record,
            audience=source.agent_id,
            nonce_state=self._nonce_state,
            expected_type="agent.result",
            expected_reply_to=request.id,
        )
        return result_payload

    def endpoint(
        self,
        path: str,
        *,
        identity: str,
        request: type[Any],
        response: type[Any],
    ) -> Any:
        return self._server_adapter().endpoint(
            path,
            identity=identity,
            request_type=request,
            response_type=response,
        )

    @property
    def router(self) -> Any:
        return self._server_adapter().router

    async def _instrument(self) -> None:
        async with self._instrument_lock:
            self._instrument_sync()

    def _instrument_sync(self) -> None:
        for source_alias, agent in self._objects.items():
            tools = getattr(agent, "tools", None)
            if isinstance(tools, list):
                agent.tools = [self._wrap_tool(tool) for tool in tools]
            handoffs = getattr(agent, "handoffs", None)
            if isinstance(handoffs, list):
                agent.handoffs = [
                    self._wrap_handoff(source_alias, self._normalize_handoff(handoff)) for handoff in handoffs
                ]

    def _normalize_handoff(self, value: Any) -> Any:
        """Convert OpenAI's ``handoffs=[agent]`` shorthand before wrapping."""

        if id(value) not in self._bindings:
            return value
        try:
            from agents import handoff
        except ImportError as exc:  # pragma: no cover - guarded by the OpenAI extra
            raise AgentAuthError("OPENAI_NOT_INSTALLED", "Install verifiable-agent-auth-sdk[openai]") from exc
        return handoff(value)

    def _wrap_tool(self, tool: Any) -> Any:
        if id(tool) in self._auth_tool_ids or id(tool) in {id(value) for value in self._wrapped_tools.values()}:
            return tool
        existing = self._wrapped_tools.get(id(tool))
        if existing is not None:
            return existing
        invoke = getattr(tool, "on_invoke_tool", None)
        if not callable(invoke) or not dataclasses.is_dataclass(tool):
            return tool
        target_agent = getattr(tool, "_agent_instance", None)
        target_alias = self._bindings.get(id(target_agent)) if target_agent is not None else None
        if target_agent is not None and target_alias is None:
            raise AgentAuthError("UNBOUND_TARGET_AGENT", "Agent.as_tool target must be bound before auth.run")

        async def authenticated(context: Any, arguments: str) -> Any:
            source_alias = self._alias_for(getattr(context, "agent", None))
            target = target_alias or source_alias
            request_payload = {"tool": getattr(tool, "name", "tool"), "arguments": json.loads(arguments or "{}")}
            request = await self._local_request(
                source_alias,
                target,
                request_payload,
                "agent.call" if target_alias else "tool.call",
            )
            result = invoke(context, arguments)
            if inspect.isawaitable(result):
                result = await result
            await self._local_response(target, source_alias, request.id, _json_value(result))
            return result

        wrapped = dataclasses.replace(tool, on_invoke_tool=authenticated)  # type: ignore[type-var]
        self._wrapped_tools[id(tool)] = wrapped
        return wrapped

    def _wrap_handoff(self, source_alias: str, handoff: Any) -> Any:
        if id(handoff) in {id(value) for value in self._wrapped_handoffs.values()}:
            return handoff
        existing = self._wrapped_handoffs.get(id(handoff))
        if existing is not None:
            return existing
        invoke = getattr(handoff, "on_invoke_handoff", None)
        target_ref = getattr(handoff, "_agent_ref", None)
        target_agent = target_ref() if callable(target_ref) else None
        target_alias = self._bindings.get(id(target_agent)) if target_agent is not None else None
        if not callable(invoke) or not dataclasses.is_dataclass(handoff):
            return handoff
        if target_alias is None:
            raise AgentAuthError("UNBOUND_HANDOFF_TARGET", "Handoff target must be bound before auth.run")

        async def authenticated(context: Any, arguments: str) -> Any:
            await self._local_request(
                source_alias,
                target_alias,
                {"handoff": getattr(handoff, "tool_name", "handoff"), "arguments": json.loads(arguments or "{}")},
                "agent.handoff",
            )
            return await invoke(context, arguments)

        wrapped = dataclasses.replace(handoff, on_invoke_handoff=authenticated)  # type: ignore[type-var]
        self._wrapped_handoffs[id(handoff)] = wrapped
        return wrapped

    async def _local_request(
        self,
        source_alias: str,
        target_alias: str,
        payload: Any,
        call_type: str,
    ) -> SignedEnvelope:
        await self._start()
        source = self._settings.agents[source_alias]
        target = self._settings.agents[target_alias]
        envelope = await sign_envelope(
            sender=source.agent_id,
            audience=target.agent_id,
            call_type=call_type,
            payload=payload,
            signer=self._signers[source_alias],
        )
        record = await self._registry.resolve(source.agent_id)
        verify_envelope(
            envelope,
            record=record,
            audience=target.agent_id,
            nonce_state=self._nonce_state,
            expected_type=call_type,
        )
        return envelope

    async def _local_response(self, source_alias: str, target_alias: str, reply_to: str, payload: Any) -> None:
        source = self._settings.agents[source_alias]
        target = self._settings.agents[target_alias]
        envelope = await sign_envelope(
            sender=source.agent_id,
            audience=target.agent_id,
            call_type="agent.result",
            payload=payload,
            signer=self._signers[source_alias],
            reply_to=reply_to,
        )
        record = await self._registry.resolve(source.agent_id)
        verify_envelope(
            envelope,
            record=record,
            audience=target.agent_id,
            nonce_state=self._nonce_state,
            expected_type="agent.result",
            expected_reply_to=reply_to,
        )

    def _alias_for(self, agent: Any) -> str:
        if agent is None or id(agent) not in self._bindings:
            raise AgentAuthError("CALLER_IDENTITY_UNKNOWN", "Active OpenAI Agent is not bound to an identity")
        return self._bindings[id(agent)]

    def _require_bound(self, agent: Any) -> None:
        self._alias_for(agent)

    def _server_adapter(self) -> Any:
        if self._server is None:
            from ._server import ServerAdapter

            self._server = ServerAdapter(self)
        return self._server


def _openai_runner() -> Any:
    try:
        from agents import Runner

        return Runner
    except ImportError as exc:
        raise AgentAuthError("OPENAI_NOT_INSTALLED", "Install verifiable-agent-auth-sdk[openai]") from exc


def _openai_tool_types() -> tuple[Any, Any]:
    try:
        from agents import FunctionTool
        from pydantic import TypeAdapter

        return FunctionTool, TypeAdapter
    except ImportError as exc:
        raise AgentAuthError("OPENAI_NOT_INSTALLED", "Install verifiable-agent-auth-sdk[openai]") from exc


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if hasattr(value, "final_output"):
        return _json_value(value.final_output)
    if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
        return value
    return str(value)


def _strict_json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    try:
        json.dumps(value, allow_nan=False, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise AgentAuthError("PAYLOAD_INVALID", "Agent call payload must be strict JSON data") from exc
    return value


def _remote_error(response: httpx.Response, request_id: str) -> AgentAuthError:
    try:
        value = response.json()
        error = value.get("error") if isinstance(value, dict) else None
        if isinstance(error, dict):
            return AgentAuthError(
                str(error.get("code", "REMOTE_REJECTED")),
                str(error.get("message", "Remote Agent rejected the request")),
                request_id=str(error.get("request_id") or request_id),
            )
    except ValueError:
        pass
    return AgentAuthError("REMOTE_REJECTED", "Remote Agent rejected the request", request_id=request_id)


def _pin_public_endpoint(endpoint: str) -> tuple[str, str, str]:
    """Resolve once and connect to that public IP while preserving Host and TLS SNI."""

    parsed = urlsplit(endpoint)
    hostname = parsed.hostname or ""
    address = sorted(resolve_public_host(hostname))[0]
    address_literal = f"[{address}]" if ":" in address else address
    netloc = address_literal if parsed.port is None else f"{address_literal}:{parsed.port}"
    return urlunsplit(parsed._replace(netloc=netloc)), parsed.netloc, hostname
