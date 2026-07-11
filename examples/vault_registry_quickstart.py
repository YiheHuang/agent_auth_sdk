"""Vault + HTTPS Registry 权威 Quick Start。"""

from __future__ import annotations

import argparse
import asyncio
import os

from agent_auth_sdk import AgentInstance, AgentVerifier, MetadataResolverConfig, RegistryClient


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def vault_verify() -> bool | str:
    value = os.getenv("AGENT_AUTH_VAULT_VERIFY", "true").strip()
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    return value


async def create_agent(role: str, key_env: str) -> AgentInstance:
    domain = required_env("AGENT_AUTH_AGENT_DOMAIN")
    return await asyncio.to_thread(
        AgentInstance.from_vault,
        domain=domain,
        name=f"quickstart/{role}",
        organization="Agent Auth Quick Start",
        endpoint=f"https://{domain}/quickstart/{role}/invoke",
        vault_addr=required_env("AGENT_AUTH_VAULT_ADDR"),
        vault_token_file=required_env("AGENT_AUTH_VAULT_TOKEN_FILE"),
        transit_mount=os.getenv("AGENT_AUTH_VAULT_TRANSIT_MOUNT", "transit"),
        key_name=required_env(key_env),
        namespace=os.getenv("AGENT_AUTH_VAULT_NAMESPACE") or None,
        verify=vault_verify(),
        capabilities=[f"quickstart.{role}"],
        environment="production",
    )


async def main() -> None:
    registry_url = required_env("AGENT_AUTH_REGISTRY_URL")
    sender, receiver = await asyncio.gather(
        create_agent("sender", "AGENT_AUTH_SENDER_KEY_NAME"),
        create_agent("receiver", "AGENT_AUTH_RECEIVER_KEY_NAME"),
    )

    async with RegistryClient(
        base_url=registry_url,
        client_id=required_env("AGENT_AUTH_REGISTRY_CLIENT_ID"),
        api_key=lambda: required_env("AGENT_AUTH_REGISTRY_API_KEY"),
    ) as registry:
        if sender.metadata is None or receiver.metadata is None:
            raise RuntimeError("Agent metadata was not initialized")
        await registry.publish(sender.metadata, signer=sender.signer)
        await registry.publish(receiver.metadata, signer=receiver.signer)

    print(f"published sender: {sender.agent_id}")
    print(f"published receiver: {receiver.agent_id}")

    signed = await sender.sign_message(
        payload={"task": "quickstart", "status": "ready"},
        recipient=receiver.agent_id,
        message_type="quickstart.request",
    )
    async with AgentVerifier(
        resolver_config=MetadataResolverConfig(registry_url=registry_url),
    ) as verifier:
        result = await verifier.verify_message(message=signed, expected_recipient=receiver.agent_id)
    if not result.ok or result.message is None:
        raise PermissionError(f"{result.code}: {result.reason}")

    print(f"verified sender: {result.agent_id}")
    print(f"verified recipient: {result.message.recipient}")
    print(f"payload: {result.message.payload}")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    asyncio.run(main())
