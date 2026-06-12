from __future__ import annotations

import os

import httpx
import pytest

from agent_identity_sdk import LocalPemSigner, build_agent_id, sign_http_request
from examples.gateway.app import create_app, load_settings


class FakeLLMClient:
    async def chat(self, *, messages, model, temperature):
        return {
            "id": "fake",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"收到 {len(messages)} 条消息，模型 {model}",
                    }
                }
            ],
        }


@pytest.mark.asyncio
async def test_gateway_invoke_and_audit() -> None:
    os.environ["AGENT_PROFILE"] = "test"
    os.environ["AGENT_GATEWAY_HOST"] = "127.0.0.1"
    os.environ["AGENT_GATEWAY_PORT"] = "8010"
    os.environ["AGENT_GATEWAY_AGENT_HOST"] = "127.0.0.1:8010"
    bootstrap_app = create_app(load_settings(), llm_client=FakeLLMClient())
    metadata_transport = httpx.ASGITransport(app=bootstrap_app)
    app = create_app(
        load_settings(),
        llm_client=FakeLLMClient(),
        http_client_factory=lambda: httpx.AsyncClient(
            transport=metadata_transport,
            base_url="http://127.0.0.1:8010",
        ),
    )
    transport = httpx.ASGITransport(app=app)
    signer = LocalPemSigner(
        private_key_pem=open("runtime/keys/private_key.pem", encoding="utf-8").read(),
        kid_value="main",
    )
    payload = {
        "messages": [{"role": "user", "content": "hello"}],
        "model": "fake-model",
        "temperature": 0.1,
    }
    signed = await sign_http_request(
        method="POST",
        url="http://127.0.0.1:8010/invoke",
        body=payload,
        agent_id=build_agent_id("127.0.0.1:8010", "llm-gateway"),
        signer=signer,
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8010") as client:
        response = await client.post("/invoke", json=payload, headers=signed.headers)
        assert response.status_code == 200
        data = response.json()
        assert data["verified_agent"] == "agent://127.0.0.1:8010/llm-gateway"
        audit = await client.get("/audit/recent")
        assert audit.status_code == 200
        assert len(audit.json()) >= 1
