"""FastAPI 上的声明式 Agent 身份认证 endpoint。"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Callable
from typing import Any, cast

from pydantic import TypeAdapter, ValidationError

from agent_auth_sdk.auth_context import AuthenticatedAgentContext
from agent_auth_sdk.errors import (
    AgentAuthenticationError,
    AgentAuthError,
    AgentAuthorizationError,
    AgentConfigurationError,
    AgentDiscoveryError,
    AgentReplayError,
    AgentTransportError,
)
from agent_auth_sdk.models import VerificationFailure
from agent_auth_sdk.remote import _validate_public_base_url, duplicate_signed_header, request_url_from_scope

from .openai_agents import _to_payload
from .openai_facade import OpenAIAgentAuth, _raise_verification

try:  # FastAPI 只在 openai-fastapi extra 中是必需依赖
    from fastapi import APIRouter, HTTPException, Request
    from fastapi.responses import JSONResponse
except ImportError:  # pragma: no cover - optional dependency gate
    APIRouter = HTTPException = Request = JSONResponse = None  # type: ignore[assignment,misc]


class AgentAuthRouter:
    """验签请求、注入 context、执行 handler 并签名响应的 FastAPI router。"""

    def __init__(
        self,
        auth: OpenAIAgentAuth,
        *,
        prefix: str = "",
        tags: list[str] | None = None,
        public_base_url: str | None = None,
    ) -> None:
        if APIRouter is None:
            raise AgentConfigurationError("Install verifiable-agent-auth-sdk[openai-fastapi]")
        self.auth = auth
        self.router = APIRouter(prefix=prefix, tags=cast(Any, tags))
        self.public_base_url = _validate_public_base_url(public_base_url)

    def __getattr__(self, name: str) -> Any:
        """让 FastAPI ``include_router(auth.router())`` 可直接工作。"""

        return getattr(self.router, name)

    def agent_endpoint(
        self,
        path: str,
        *,
        request_model: type[Any],
        methods: tuple[str, ...] = ("POST",),
        required_capability: str | None = None,
        message_type: str = "agent.call.result",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        request_adapter = TypeAdapter(request_model)

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            async def endpoint(request: Request) -> JSONResponse:  # type: ignore[valid-type]
                request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
                try:
                    body = await request.body()
                    duplicate = duplicate_signed_header(request.scope.get("headers", []))
                    if duplicate:
                        return _error_response(
                            400,
                            "DUPLICATE_SIGNED_HEADER",
                            f"Duplicate signed header: {duplicate}",
                            request_id,
                        )
                    headers = {key.lower(): value for key, value in request.headers.items()}
                    verification = await self.auth.verifier.verify_http(
                        method=request.method,
                        url=request_url_from_scope(
                            request.scope,
                            headers=headers,
                            public_base_url=self.public_base_url,
                        ),
                        headers=headers,
                        body=body,
                        request_id=request_id,
                    )
                    _raise_verification(verification)
                    if isinstance(verification, VerificationFailure):  # type narrowing for static checkers
                        raise AgentAuthenticationError(verification.reason, code=verification.code)
                    if required_capability and (
                        verification.metadata is None or required_capability not in verification.metadata.capabilities
                    ):
                        raise AgentAuthorizationError(
                            "Authenticated Agent lacks the required capability",
                            code="CAPABILITY_DENIED",
                            agent_id=verification.agent_id,
                            request_id=request_id,
                        )
                    if self.auth.authorization_policy is not None:
                        authorized = await self.auth.verifier.authorize(
                            verification,
                            policy=self.auth.authorization_policy,
                            capability=required_capability,
                        )
                        if isinstance(authorized, VerificationFailure):
                            raise AgentAuthorizationError(
                                "Authenticated Agent is not allowed to call this endpoint",
                                code=authorized.code,
                                agent_id=verification.agent_id,
                                request_id=request_id,
                            )
                    model = request_adapter.validate_json(body)
                    context = self.auth.authenticated_context(verification)
                    request.scope.setdefault("state", {})["agent_auth"] = context
                    result = handler(context, model)
                    if inspect.isawaitable(result):
                        result = await result
                    signed = await self.auth.agent.sign_message(
                        payload=_to_payload(result),
                        recipient=context.agent_id,
                        message_type=message_type,
                    )
                    return JSONResponse(signed.model_dump(mode="json"), headers={"x-request-id": request_id})
                except ValidationError:
                    return _error_response(
                        422, "REQUEST_SCHEMA_INVALID", "Request body does not match schema", request_id
                    )
                except AgentAuthorizationError as exc:
                    return _agent_error_response(403, exc, request_id)
                except AgentReplayError as exc:
                    return _agent_error_response(409, exc, request_id)
                except (AgentDiscoveryError, AgentTransportError) as exc:
                    return _agent_error_response(503, exc, request_id)
                except AgentAuthenticationError as exc:
                    return _agent_error_response(401, exc, request_id)
                except AgentAuthError as exc:
                    return _agent_error_response(500, exc, request_id)

            endpoint.__name__ = handler.__name__
            endpoint.__doc__ = handler.__doc__
            self.router.add_api_route(path, endpoint, methods=list(methods), response_model=None)
            return handler

        return decorator

    endpoint = agent_endpoint


async def authenticated_agent(request: Request) -> AuthenticatedAgentContext:  # type: ignore[valid-type]
    """可用于 ``Depends(authenticated_agent)`` 的认证上下文依赖。"""

    context = getattr(request.state, "agent_auth", None)
    if not isinstance(context, AuthenticatedAgentContext):
        if HTTPException is None:  # pragma: no cover
            raise AgentConfigurationError("Install verifiable-agent-auth-sdk[openai-fastapi]")
        raise HTTPException(status_code=401, detail={"code": "AUTHENTICATION_REQUIRED"})
    return context


def _agent_error_response(status: int, error: AgentAuthError, request_id: str) -> JSONResponse:
    return _error_response(status, error.code, error.message, request_id)


def _error_response(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(  # type: ignore[operator]
        {"error": {"code": code, "message": message, "request_id": request_id}},
        status_code=status,
        headers={"x-request-id": request_id},
    )
