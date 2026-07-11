"""需要 OPENAI/Vault/Registry 环境；调用 remote_server 并验证响应。"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from agents import RunContextWrapper
from pydantic import BaseModel

from agent_auth_sdk import OpenAIAgentAuth, build_agent_id
from agent_auth_sdk.integrations.openai_agents import OpenAIAgentsAuthConfig
from examples._shared import required_env, vault_verify_from_env


class SpecialistRequest(BaseModel):
    question: str


class SpecialistResult(BaseModel):
    answer: str


def config() -> OpenAIAgentsAuthConfig:
    registry_url = required_env("AGENT_AUTH_REGISTRY_URL").rstrip("/")
    return OpenAIAgentsAuthConfig(
        roles=("caller",),
        mode="vault",
        domain=required_env("AGENT_AUTH_AGENT_DOMAIN"),
        organization="Agent Auth OpenAI remote example",
        environment="production",
        runtime_dir=Path(".agent-auth/runtime-openai-client"),
        registry_url=registry_url,
        registry_publish_url=f"{registry_url}/v1/agents/publish",
        registry_client_id=required_env("AGENT_AUTH_REGISTRY_CLIENT_ID"),
        registry_api_key=required_env("AGENT_AUTH_REGISTRY_API_KEY"),
        profile="strict",
        vault_addr=required_env("AGENT_AUTH_VAULT_ADDR"),
        vault_token_file=required_env("AGENT_AUTH_VAULT_TOKEN_FILE"),
        vault_transit_mount=os.getenv("AGENT_AUTH_VAULT_TRANSIT_MOUNT", "transit"),
        vault_namespace=os.getenv("AGENT_AUTH_VAULT_NAMESPACE") or None,
        vault_verify=vault_verify_from_env(),
        vault_key_names={"caller": required_env("AGENT_AUTH_CALLER_KEY_NAME")},
        auto_create_vault_keys=False,
    )


async def main() -> None:
    auth = await OpenAIAgentAuth.from_config(config(), identity="caller")
    domain = required_env("AGENT_AUTH_AGENT_DOMAIN")
    tool = auth.remote_agent_tool(
        name="call_specialist",
        target=build_agent_id(domain, "specialist"),
        url=required_env("AGENT_AUTH_OPENAI_REMOTE_URL"),
        input_type=SpecialistRequest,
        output_type=SpecialistResult,
    )
    result = await tool.on_invoke_tool(
        RunContextWrapper(context=None),
        '{"question":"Why must recipient be signed?"}',
    )
    print(result)
    print([event.as_dict() for event in auth.events()])
    await auth.__aexit__()


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    asyncio.run(main())
