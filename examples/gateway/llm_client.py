"""调用 OpenAI 兼容接口的最小封装。"""

from __future__ import annotations

from typing import Any

import httpx


class OpenAICompatClient:
    def __init__(self, *, base_url: str, api_key: str, timeout_seconds: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds

    async def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base_url}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                },
            )
            response.raise_for_status()
            return response.json()

