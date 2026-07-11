"""调用签名 HTTP receiver，并验证其签名响应。"""

from __future__ import annotations

import argparse
import asyncio
import os

from agent_auth_sdk import AgentInstance, AgentVerifier, MetadataResolverConfig, RemoteAgentClient, build_agent_id
from examples._shared import required_env, vault_verify_from_env


async def main() -> None:
    domain = required_env("AGENT_AUTH_AGENT_DOMAIN")
    sender = await asyncio.to_thread(
        AgentInstance.from_vault,
        domain=domain,
        name=os.getenv("AGENT_AUTH_SENDER_NAME", "quickstart/sender"),
        organization="Agent Auth remote example",
        endpoint=f"https://{domain}/quickstart/sender/invoke",
        vault_addr=required_env("AGENT_AUTH_VAULT_ADDR"),
        vault_token_file=required_env("AGENT_AUTH_VAULT_TOKEN_FILE"),
        transit_mount=os.getenv("AGENT_AUTH_VAULT_TRANSIT_MOUNT", "transit"),
        key_name=required_env("AGENT_AUTH_SENDER_KEY_NAME"),
        namespace=os.getenv("AGENT_AUTH_VAULT_NAMESPACE") or None,
        verify=vault_verify_from_env(),
        environment="production",
    )
    receiver_name = os.getenv("AGENT_AUTH_RECEIVER_NAME", "quickstart/receiver")
    async with AgentVerifier(
        resolver_config=MetadataResolverConfig(registry_url=required_env("AGENT_AUTH_REGISTRY_URL")),
    ) as verifier:
        async with RemoteAgentClient(sender=sender, verifier=verifier) as remote:
            result = await remote.call(
                target_url=required_env("AGENT_AUTH_RECEIVER_URL"),
                target_agent_id=build_agent_id(domain, receiver_name),
                payload={"task": "remote-authenticated-call"},
            )
    print(result)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    asyncio.run(main())
