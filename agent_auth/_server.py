"""FastAPI endpoint：验签输入、注入 AuthContext、签名输出。"""

from __future__ import annotations

import inspect
import uuid
from typing import Any

from ._errors import AgentAuthError
from ._protocol import SignedEnvelope, sign_envelope, verify_envelope


class ServerAdapter:
    def __init__(self, auth: Any) -> None:
        try:
            from fastapi import APIRouter
        except ImportError as exc:
            raise AgentAuthError("SERVER_NOT_INSTALLED", "Install verifiable-agent-auth-sdk[server]") from exc
        self.auth = auth
        self.router = APIRouter()

    def endpoint(
        self,
        path: str,
        *,
        identity: str,
        request_type: type[Any],
        response_type: type[Any],
    ) -> Any:
        try:
            from fastapi import Request
            from fastapi.responses import JSONResponse
            from pydantic import TypeAdapter, ValidationError
        except ImportError as exc:  # pragma: no cover - constructor already checks
            raise AgentAuthError("SERVER_NOT_INSTALLED", "Install verifiable-agent-auth-sdk[server]") from exc
        if identity not in self.auth._settings.agents:
            raise AgentAuthError("IDENTITY_NOT_CONFIGURED", f"Unknown endpoint identity: {identity}")
        request_adapter = TypeAdapter(request_type)
        response_adapter = TypeAdapter(response_type)

        def decorate(handler: Any) -> Any:
            async def route(http_request: Request) -> Any:
                request_id = http_request.headers.get("x-request-id") or str(uuid.uuid4())
                try:
                    body = await http_request.body()
                    if len(body) > 1024 * 1024:
                        raise AgentAuthError("REQUEST_TOO_LARGE", "Signed request body exceeds 1 MiB")
                    raw = await http_request.json()
                    if not isinstance(raw, dict):
                        raise AgentAuthError("ENVELOPE_INVALID", "Request must contain a signed envelope")
                    envelope = SignedEnvelope.from_dict(raw)
                    request_id = envelope.id
                    await self.auth._start()
                    target = self.auth._settings.agents[identity]
                    sender = await self.auth._registry.resolve(envelope.sender)
                    context, payload = verify_envelope(
                        envelope,
                        record=sender,
                        audience=target.agent_id,
                        nonce_state=self.auth._nonce_state,
                        expected_type="agent.call",
                    )
                    request_value = request_adapter.validate_python(payload)
                    result = handler(context, request_value)
                    if inspect.isawaitable(result):
                        result = await result
                    result_value = response_adapter.validate_python(result)
                    reply = await sign_envelope(
                        sender=target.agent_id,
                        audience=context.sender,
                        call_type="agent.result",
                        payload=_model_value(result_value),
                        signer=self.auth._signers[identity],
                        reply_to=context.request_id,
                    )
                    return JSONResponse(reply.as_dict(), headers={"X-Request-ID": request_id})
                except ValidationError:
                    return _error_response("SCHEMA_INVALID", "Request or response schema is invalid", request_id, 422)
                except AgentAuthError as exc:
                    return _error_response(exc.code, exc.message, exc.request_id or request_id, _status(exc.code))
                except (ValueError, TypeError):
                    return _error_response("REQUEST_INVALID", "Request is invalid", request_id, 400)

            route.__name__ = handler.__name__
            route.__doc__ = handler.__doc__
            route.__annotations__["http_request"] = Request
            self.router.add_api_route(path, route, methods=["POST"], response_model=None)
            return handler

        return decorate


def _model_value(value: Any) -> Any:
    return value.model_dump(mode="json") if hasattr(value, "model_dump") else value


def _status(code: str) -> int:
    if code == "NONCE_REPLAYED":
        return 409
    if code in {"AGENT_NOT_FOUND", "REGISTRY_UNAVAILABLE"}:
        return 503
    if code in {"REQUEST_TOO_LARGE", "ENVELOPE_INVALID", "PAYLOAD_INVALID"}:
        return 400
    return 401


def _error_response(code: str, message: str, request_id: str, status: int) -> Any:
    from fastapi.responses import JSONResponse

    return JSONResponse(
        {"error": {"code": code, "message": message, "request_id": request_id}},
        status_code=status,
        headers={"X-Request-ID": request_id},
    )
