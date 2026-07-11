"""无需 Registry/Vault 的签名消息、篡改和重放示例。"""

from __future__ import annotations

import asyncio

import httpx

from agent_auth_sdk import TEST_PROFILE, AgentVerifier, MetadataResolverConfig, VerificationConfig

from ._shared import local_agent, registry_transport


async def main() -> None:
    sender = local_agent("sender")
    receiver = local_agent("receiver")
    transport = registry_transport([sender, receiver])

    async with httpx.AsyncClient(transport=transport, base_url="http://registry.test") as client:
        async with AgentVerifier(
            verification_config=VerificationConfig(profile=TEST_PROFILE),
            resolver_config=MetadataResolverConfig(
                profile=TEST_PROFILE,
                registry_url="http://registry.test",
            ),
            http_client=client,
        ) as verifier:
            signed = await sender.sign_message(
                payload={"task": "review", "priority": 2},
                recipient=receiver.agent_id,
                message_type="example.task",
            )
            verified = await verifier.verify_message(message=signed, expected_recipient=receiver.agent_id)
            print(f"verified: {verified.ok}, sender: {verified.agent_id}")

            replayed = await verifier.verify_message(message=signed, expected_recipient=receiver.agent_id)
            print(f"replay: {replayed.ok}, code: {replayed.code}")

            fresh = await sender.sign_message(
                payload={"task": "review", "priority": 2},
                recipient=receiver.agent_id,
                message_type="example.task",
            )
            tampered = fresh.model_dump(mode="json")
            tampered["payload"]["priority"] = 9
            rejected = await verifier.verify_message(message=tampered, expected_recipient=receiver.agent_id)
            print(f"tampered: {rejected.ok}, code: {rejected.code}")


if __name__ == "__main__":
    asyncio.run(main())
