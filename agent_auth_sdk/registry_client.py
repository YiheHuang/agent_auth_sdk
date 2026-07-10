"""中心 Registry 的类型化异步客户端。"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

import httpx

from .crypto import Signer
from .models import AgentKey, AgentMetadata
from .publish import (
    add_key_in_registry,
    publish_to_registry,
    revoke_agent_in_registry,
    revoke_key_in_registry,
    rotate_key_in_registry,
)

CredentialProvider = Callable[[], str | Awaitable[str]]


class RegistryClient:
    """集中管理 Registry URL、developer credential 与 HTTP 连接。"""

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        api_key: str | CredentialProvider,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
        allow_insecure_http: bool = False,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain userinfo")
        if parsed.scheme != "https" and not allow_insecure_http:
            raise ValueError("base_url must use HTTPS; set allow_insecure_http=True only for local tests")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self._api_key = api_key
        self.timeout_seconds = timeout_seconds
        self._http_client = http_client
        self._owns_client = http_client is None

    async def __aenter__(self) -> RegistryClient:
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

    async def _credential(self) -> str:
        value = self._api_key() if callable(self._api_key) else self._api_key
        if inspect.isawaitable(value):
            value = await value
        if not value:
            raise ValueError("Registry credential provider returned an empty API key")
        return value

    def _endpoint(self, operation: str) -> str:
        return f"{self.base_url}/v1/agents/{operation}"

    async def publish(self, metadata: AgentMetadata, *, signer: Signer) -> dict:
        return await publish_to_registry(
            metadata,
            registry_url=self._endpoint("publish"),
            client_id=self.client_id,
            api_key=await self._credential(),
            signer=signer,
            http_client=self._client(),
            timeout_seconds=self.timeout_seconds,
        )

    async def rotate_key(
        self,
        *,
        agent_id: str,
        new_key: AgentKey,
        current_signer: Signer,
        new_signer: Signer,
    ) -> dict:
        return await rotate_key_in_registry(
            agent_id=agent_id,
            new_key=new_key,
            registry_url=self._endpoint("rotate-key"),
            client_id=self.client_id,
            api_key=await self._credential(),
            current_signer=current_signer,
            new_signer=new_signer,
            http_client=self._client(),
            timeout_seconds=self.timeout_seconds,
        )

    async def add_key(
        self,
        *,
        agent_id: str,
        new_key: AgentKey,
        current_signer: Signer,
        new_signer: Signer,
    ) -> dict:
        return await add_key_in_registry(
            agent_id=agent_id,
            new_key=new_key,
            registry_url=self._endpoint("add-key"),
            client_id=self.client_id,
            api_key=await self._credential(),
            current_signer=current_signer,
            new_signer=new_signer,
            http_client=self._client(),
            timeout_seconds=self.timeout_seconds,
        )

    async def revoke_key(self, *, agent_id: str, kid_to_revoke: str, current_signer: Signer) -> dict:
        return await revoke_key_in_registry(
            agent_id=agent_id,
            kid_to_revoke=kid_to_revoke,
            registry_url=self._endpoint("revoke-key"),
            client_id=self.client_id,
            api_key=await self._credential(),
            current_signer=current_signer,
            http_client=self._client(),
            timeout_seconds=self.timeout_seconds,
        )

    async def revoke_agent(self, *, agent_id: str, current_signer: Signer) -> dict:
        return await revoke_agent_in_registry(
            agent_id=agent_id,
            registry_url=self._endpoint("revoke"),
            client_id=self.client_id,
            api_key=await self._credential(),
            current_signer=current_signer,
            http_client=self._client(),
            timeout_seconds=self.timeout_seconds,
        )
