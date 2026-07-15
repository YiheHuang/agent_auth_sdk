"""跨进程 HTTP Agent 认证边界。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from .agent import AgentInstance
from .auth_context import AuthenticatedAgentContext
from .errors import (
    AgentAuthenticationError,
    AgentAuthorizationError,
    AgentDiscoveryError,
    AgentReplayError,
    AgentTransportError,
)
from .http_utils import canonical_json_bytes
from .models import SignedAgentMessage, VerificationFailure
from .verifier import AgentVerifier


class RemoteAgentClient:
    """发送已签名 HTTP 请求，并要求对端返回目标 Agent 签名的消息。"""

    def __init__(
        self,
        *,
        sender: AgentInstance,
        verifier: AgentVerifier,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.sender = sender
        self.verifier = verifier
        self._http_client = http_client
        self._owns_client = http_client is None

    async def __aenter__(self) -> RemoteAgentClient:
        self._client()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(follow_redirects=False)
        return self._http_client

    async def call(
        self,
        *,
        target_url: str,
        target_agent_id: str,
        payload: object,
        message_type: str = "agent.call.result",
        request_id: str | None = None,
    ) -> Any:
        body = canonical_json_bytes(payload)
        request_headers = {"content-type": "application/json"}
        if request_id:
            request_headers["x-request-id"] = request_id
        signed = await self.sender.sign_http(
            method="POST",
            url=target_url,
            body=body,
            headers=request_headers,
        )
        try:
            response = await self._client().post(target_url, content=body, headers=signed.headers)
        except httpx.HTTPError as exc:
            raise AgentTransportError(
                "Remote Agent request failed",
                agent_id=target_agent_id,
                request_id=request_id,
            ) from exc
        response_request_id = response.headers.get("x-request-id") or request_id
        if response.status_code >= 400:
            raise _remote_error(response, target_agent_id=target_agent_id, request_id=response_request_id)
        try:
            message = SignedAgentMessage.model_validate(response.json())
        except Exception as exc:
            raise AgentAuthenticationError(
                "Remote Agent returned an unsigned or malformed response",
                code="REMOTE_RESPONSE_INVALID",
                agent_id=target_agent_id,
                request_id=response_request_id,
            ) from exc
        if message.agent_id != target_agent_id or message.message_type != message_type:
            raise AgentAuthenticationError(
                "Remote Agent response identity or message_type mismatch",
                code="REMOTE_RESPONSE_MISMATCH",
                agent_id=target_agent_id,
                request_id=response_request_id,
            )
        verified = await self.verifier.verify_message(
            message=message,
            expected_recipient=self.sender.agent_id,
        )
        if isinstance(verified, VerificationFailure):
            raise AgentAuthenticationError(
                verified.reason,
                code=verified.code,
                agent_id=target_agent_id,
                request_id=response_request_id,
            )
        if verified.message is None:
            raise AgentAuthenticationError(
                "Verification succeeded without a signed message",
                code="REMOTE_RESPONSE_INVALID",
                agent_id=target_agent_id,
                request_id=response_request_id,
            )
        return verified.message.payload


ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
ASGISend = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[dict[str, Any], ASGIReceive, ASGISend], Awaitable[None]]


class AgentAuthASGIMiddleware:
    """在 ASGI 请求进入业务 handler 前验证 x-agent-* HTTP 签名。"""

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: AgentVerifier,
        max_body_bytes: int = 1_048_576,
        public_base_url: str | None = None,
    ) -> None:
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.verifier = verifier
        self.max_body_bytes = max_body_bytes
        self.public_base_url = _validate_public_base_url(public_base_url)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        total_body_bytes = 0
        more = True
        while more:
            event = await receive()
            if event.get("type") == "http.disconnect":
                return
            if event.get("type") != "http.request":
                continue
            chunk = event.get("body", b"")
            chunks.append(chunk)
            total_body_bytes += len(chunk)
            if total_body_bytes > self.max_body_bytes:
                await _send_json_error(send, 413, "BODY_TOO_LARGE", "Request body exceeds the configured limit")
                return
            more = bool(event.get("more_body", False))
        body = b"".join(chunks)
        raw_headers = scope.get("headers", [])
        duplicate = duplicate_signed_header(raw_headers)
        if duplicate:
            await _send_json_error(send, 400, "DUPLICATE_SIGNED_HEADER", f"Duplicate signed header: {duplicate}")
            return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in raw_headers}
        url = request_url_from_scope(scope, headers=headers, public_base_url=self.public_base_url)
        result = await self.verifier.verify_http(
            method=scope.get("method", "GET"),
            url=url,
            headers=headers,
            body=body,
        )
        if not result.ok:
            await _send_json_error(send, 401, result.code, result.reason)
            return

        state = scope.setdefault("state", {})
        state["agent_auth"] = AuthenticatedAgentContext(
            agent_id=result.agent_id,
            kid=result.kid,
            capabilities=tuple(result.metadata.capabilities) if result.metadata is not None else (),
            request_id=result.request_id,
        )
        state["agent_auth_verification"] = result
        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)


async def _send_json_error(send: ASGISend, status: int, code: str, reason: str) -> None:
    payload = canonical_json_bytes({"error": {"code": code, "message": reason, "request_id": None}})
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


_SIGNED_HEADERS = {
    "host",
    "x-agent-id",
    "x-agent-kid",
    "x-agent-timestamp",
    "x-agent-nonce",
    "x-agent-signature",
    "x-agent-signature-input",
}


def duplicate_signed_header(raw_headers: list[tuple[bytes, bytes]]) -> str | None:
    seen: set[str] = set()
    for raw_name, _ in raw_headers:
        name = raw_name.decode("latin-1").lower()
        if name not in _SIGNED_HEADERS:
            continue
        if name in seen:
            return name
        seen.add(name)
    return None


def request_url_from_scope(
    scope: Mapping[str, Any],
    *,
    headers: dict[str, str],
    public_base_url: str | None = None,
) -> str:
    path = scope.get("raw_path") or scope.get("path", "/").encode("utf-8")
    query = scope.get("query_string", b"")
    if public_base_url:
        base = public_base_url.rstrip("/")
    else:
        base = f"{scope.get('scheme', 'https')}://{headers.get('host', '')}"
    url = f"{base}{path.decode('latin-1')}"
    if query:
        url += "?" + query.decode("latin-1")
    return url


def _validate_public_base_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
        raise ValueError("public_base_url must be an absolute HTTP(S) origin without a path")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("public_base_url must not contain userinfo, query, or fragment")
    return value.rstrip("/")


def _remote_error(response: httpx.Response, *, target_agent_id: str, request_id: str | None) -> Exception:
    code = "REMOTE_REQUEST_REJECTED"
    message = "Remote Agent rejected the request"
    try:
        payload = response.json()
        error = payload.get("error", payload) if isinstance(payload, dict) else {}
        if isinstance(error, dict):
            raw_code = error.get("code")
            raw_message = error.get("message") or error.get("reason")
            if isinstance(raw_code, str) and raw_code:
                code = raw_code[:100]
            if isinstance(raw_message, str) and raw_message and not any(ch in raw_message for ch in "\r\n"):
                message = raw_message[:300]
            raw_request_id = error.get("request_id")
            if isinstance(raw_request_id, str) and raw_request_id:
                request_id = raw_request_id[:200]
    except (ValueError, TypeError):
        pass
    if response.status_code == 403:
        return AgentAuthorizationError(
            message,
            code=code,
            agent_id=target_agent_id,
            request_id=request_id,
        )
    if response.status_code == 409 or code == "NONCE_REPLAYED":
        return AgentReplayError(
            message,
            code=code,
            agent_id=target_agent_id,
            request_id=request_id,
        )
    if response.status_code == 401 or response.status_code in {400, 422}:
        return AgentAuthenticationError(
            message,
            code=code,
            agent_id=target_agent_id,
            request_id=request_id,
        )
    if code in {"METADATA_FETCH_FAILED", "INVALID_METADATA"}:
        return AgentDiscoveryError(
            message,
            code=code,
            agent_id=target_agent_id,
            request_id=request_id,
        )
    return AgentTransportError(
        "Remote Agent is unavailable",
        code=code,
        agent_id=target_agent_id,
        request_id=request_id,
        details={"status_code": response.status_code, "remote_code": code},
    )
