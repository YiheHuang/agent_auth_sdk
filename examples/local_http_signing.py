"""无需外部服务的 HTTP body 签名与篡改检测示例。"""

from __future__ import annotations

import asyncio

import httpx

from agent_auth_sdk import TEST_PROFILE, AgentVerifier, MetadataResolverConfig, VerificationConfig
from agent_auth_sdk.http_utils import canonical_json_bytes

from ._shared import local_agent, registry_transport


async def main() -> None:
    sender = local_agent("http-sender")
    body = canonical_json_bytes({"action": "calculate", "value": 42})
    target_url = "http://receiver.test/invoke"
    signed = await sender.sign_http(
        method="POST",
        url=target_url,
        body=body,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient(
        transport=registry_transport([sender]),
        base_url="http://registry.test",
    ) as client:
        async with AgentVerifier(
            verification_config=VerificationConfig(profile=TEST_PROFILE),
            resolver_config=MetadataResolverConfig(profile=TEST_PROFILE, registry_url="http://registry.test"),
            http_client=client,
        ) as verifier:
            verified = await verifier.verify_http(
                method="POST",
                url=target_url,
                headers=signed.headers,
                body=body,
            )
            print(f"verified: {verified.ok}, sender: {verified.agent_id}")

            altered = canonical_json_bytes({"action": "calculate", "value": 43})
            rejected = await verifier.verify_http(
                method="POST",
                url=target_url,
                headers=signed.headers,
                body=altered,
            )
            print(f"tampered: {rejected.ok}, code: {rejected.code}")


if __name__ == "__main__":
    asyncio.run(main())
