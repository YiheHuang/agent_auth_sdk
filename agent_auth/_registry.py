"""Registry resolve 与 mutation 客户端。"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from ._errors import AgentAuthError
from ._identity import parse_agent_id, validate_endpoint
from ._protocol import SignedEnvelope
from ._types import AgentRecord


class Registry:
    def __init__(
        self,
        base_url: str | None,
        *,
        strict: bool,
        client_id: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url
        self.strict = strict
        self.client_id = client_id
        self._client = client
        self._owns_client = client is None
        self._cache: dict[str, tuple[float, AgentRecord, str | None]] = {}
        self._dev_records: dict[str, AgentRecord] = {}

    async def start(self) -> None:
        if self.base_url and self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url + "/",
                timeout=10,
                follow_redirects=False,
            )

    def add_dev_record(self, record: AgentRecord) -> None:
        self._dev_records[record.agent_id] = record

    async def health(self) -> None:
        """Check Registry readiness without requiring an identity to exist."""

        if not self.base_url or self._client is None:
            raise AgentAuthError("REGISTRY_UNAVAILABLE", "Registry is not configured")
        try:
            response = await self._client.get("health/ready")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AgentAuthError("REGISTRY_UNAVAILABLE", "Registry readiness check failed") from exc

    async def resolve(self, agent_id: str, *, refresh: bool = False) -> AgentRecord:
        parse_agent_id(agent_id, strict=self.strict)
        if agent_id in self._dev_records:
            return self._dev_records[agent_id]
        cached = self._cache.get(agent_id)
        if cached and not refresh and cached[0] > time.monotonic():
            return cached[1]
        if not self.base_url or self._client is None:
            raise AgentAuthError("AGENT_NOT_FOUND", "Agent identity is not available", agent_id=agent_id)
        headers: dict[str, str] = {}
        if cached and cached[2]:
            headers["If-None-Match"] = cached[2]
        try:
            response = await self._client.get("v1/agents/resolve", params={"agent_id": agent_id}, headers=headers)
            if response.status_code == 304 and cached:
                self._cache[agent_id] = (time.monotonic() + 300, cached[1], cached[2])
                return cached[1]
            if response.status_code == 404:
                raise AgentAuthError("AGENT_NOT_FOUND", "Agent is not registered", agent_id=agent_id)
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            record = AgentRecord.from_dict(value)
            if record.agent_id != agent_id:
                raise AgentAuthError("REGISTRY_SUBJECT_MISMATCH", "Registry returned a different Agent identity")
            validate_endpoint(record.agent_id, record.endpoint, strict=self.strict)
            self._cache[agent_id] = (time.monotonic() + 300, record, response.headers.get("etag"))
            return record
        except AgentAuthError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise AgentAuthError("REGISTRY_UNAVAILABLE", "Registry resolve failed", agent_id=agent_id) from exc

    async def mutate(self, envelope: SignedEnvelope) -> dict[str, Any]:
        if not self.base_url or self._client is None:
            raise AgentAuthError("REGISTRY_UNAVAILABLE", "Registry is not configured")
        api_key = os.getenv("AGENT_AUTH_REGISTRY_API_KEY")
        if not self.client_id or not api_key:
            raise AgentAuthError("REGISTRY_CREDENTIALS_MISSING", "Registry client_id and API key are required")
        try:
            response = await self._client.post(
                "v1/agents",
                json=envelope.as_dict(),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "X-Registry-Client-ID": self.client_id,
                },
            )
            if response.status_code >= 400:
                code = _error_code(response)
                raise AgentAuthError(code, "Registry mutation was rejected", request_id=envelope.id)
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            self._cache.pop(envelope.sender, None)
            return value
        except AgentAuthError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise AgentAuthError("REGISTRY_UNAVAILABLE", "Registry mutation failed") from exc

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
        self._client = None


def _error_code(response: httpx.Response) -> str:
    try:
        value = response.json()
        if isinstance(value, dict):
            detail = value.get("detail") or value.get("error")
            if isinstance(detail, str):
                return detail
            if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                return str(detail["code"])
    except ValueError:
        pass
    return f"REGISTRY_HTTP_{response.status_code}"
