"""面向应用的一站式验签器。"""

from __future__ import annotations

from typing import Protocol

import httpx

from .config import MetadataResolverConfig, VerificationConfig
from .errors import VerificationErrorCode
from .messaging import verify_agent_message
from .models import SignedAgentMessage, VerificationFailure, VerificationSuccess
from .stores import InMemoryMetadataCache, InMemoryNonceStore, MetadataCache, NonceStore
from .verification import verify_http_request

VerificationResult = VerificationSuccess | VerificationFailure


class AuthorizationPolicy(Protocol):
    """业务授权策略；认证成功不自动代表具有调用权限。"""

    async def authorize(self, result: VerificationSuccess, *, capability: str | None = None) -> bool: ...


class AgentVerifier:
    """集中管理 HTTP client、nonce store、metadata cache 与验签配置。"""

    def __init__(
        self,
        *,
        nonce_store: NonceStore | None = None,
        cache: MetadataCache | None = None,
        verification_config: VerificationConfig | None = None,
        resolver_config: MetadataResolverConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.nonce_store = nonce_store or InMemoryNonceStore()
        self.cache = cache or InMemoryMetadataCache()
        self.verification_config = verification_config or VerificationConfig()
        self.resolver_config = resolver_config
        self._http_client = http_client
        self._owns_client = http_client is None

    async def __aenter__(self) -> AgentVerifier:
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

    async def verify_http(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | str | dict | list | None,
        request_id: str | None = None,
    ) -> VerificationResult:
        return await verify_http_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            nonce_store=self.nonce_store,
            http_client=self._client(),
            cache=self.cache,
            config=self.verification_config,
            resolver_config=self.resolver_config,
            request_id=request_id,
        )

    async def verify_message(
        self,
        *,
        message: SignedAgentMessage | dict,
        expected_recipient: str | None = None,
    ) -> VerificationResult:
        return await verify_agent_message(
            message=message,
            nonce_store=self.nonce_store,
            http_client=self._client(),
            cache=self.cache,
            config=self.verification_config,
            resolver_config=self.resolver_config,
            expected_recipient=expected_recipient,
        )

    async def authorize(
        self,
        result: VerificationResult,
        *,
        policy: AuthorizationPolicy,
        capability: str | None = None,
    ) -> VerificationResult:
        """在认证成功后显式执行应用授权策略。"""

        if isinstance(result, VerificationFailure):
            return result
        try:
            allowed = await policy.authorize(result, capability=capability)
        except Exception:
            allowed = False
        if allowed:
            return result
        return VerificationFailure(
            code=VerificationErrorCode.POLICY_REJECTED.value,
            reason="Authorization policy rejected the authenticated Agent",
        )
