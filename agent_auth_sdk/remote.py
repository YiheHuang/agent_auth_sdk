"""跨进程 HTTP Agent 认证边界。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from .agent import AgentInstance
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
    ) -> Any:
        body = canonical_json_bytes(payload)
        signed = await self.sender.sign_http(
            method="POST",
            url=target_url,
            body=body,
            headers={"content-type": "application/json"},
        )
        response = await self._client().post(target_url, content=body, headers=signed.headers)
        response.raise_for_status()
        try:
            message = SignedAgentMessage.model_validate(response.json())
        except Exception as exc:
            raise PermissionError("Remote Agent returned an unsigned or malformed response") from exc
        if message.agent_id != target_agent_id or message.message_type != message_type:
            raise PermissionError("Remote Agent response identity or message_type mismatch")
        verified = await self.verifier.verify_message(
            message=message,
            expected_recipient=self.sender.agent_id,
        )
        if isinstance(verified, VerificationFailure):
            raise PermissionError(f"{verified.code}: {verified.reason}")
        if verified.message is None:
            raise PermissionError("Verification succeeded without a signed message")
        return verified.message.payload


ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
ASGISend = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[dict[str, Any], ASGIReceive, ASGISend], Awaitable[None]]


class AgentAuthASGIMiddleware:
    """在 ASGI 请求进入业务 handler 前验证 x-agent-* HTTP 签名。"""

    def __init__(self, app: ASGIApp, *, verifier: AgentVerifier, max_body_bytes: int = 1_048_576) -> None:
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.verifier = verifier
        self.max_body_bytes = max_body_bytes

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
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        host = headers.get("host", "")
        path = scope.get("raw_path") or scope.get("path", "/").encode("utf-8")
        query = scope.get("query_string", b"")
        url = f"{scope.get('scheme', 'https')}://{host}{path.decode('latin-1')}"
        if query:
            url += "?" + query.decode("latin-1")
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
        state["agent_auth"] = result
        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)


async def _send_json_error(send: ASGISend, status: int, code: str, reason: str) -> None:
    payload = canonical_json_bytes({"code": code, "reason": reason})
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
