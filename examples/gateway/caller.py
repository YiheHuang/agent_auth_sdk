"""调用方示例：使用 SDK 生成签名请求并调用网关。"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx

from agent_identity_sdk import LocalPemSigner, build_agent_id, sign_http_request


async def main() -> None:
    """读取环境变量后发起一次真实的 SDK 签名调用。"""

    private_key_path = Path("runtime/keys/private_key.pem")
    signer = LocalPemSigner(private_key_pem=private_key_path.read_text(encoding="utf-8"), kid_value="main")
    body = {
        "messages": [{"role": "user", "content": "请介绍一下 Agent 身份认证 SDK 的意义。"}],
        "model": "gpt-4o-mini",
        "temperature": 0.2,
    }
    gateway_url = os.getenv("AGENT_CALLER_URL", "http://192.144.228.237:8010/invoke")
    caller_host = os.getenv("AGENT_CALLER_HOST", "192.144.228.237:8010")
    caller_name = os.getenv("AGENT_CALLER_NAME", "llm-gateway")
    signed = await sign_http_request(
        method="POST",
        url=gateway_url,
        body=body,
        agent_id=build_agent_id(caller_host, caller_name),
        signer=signer,
    )
    async with httpx.AsyncClient() as client:
        response = await client.post(gateway_url, json=body, headers=signed.headers)
        print(json.dumps(response.json(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
