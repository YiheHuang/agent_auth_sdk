"""启动：uvicorn examples.openai_agents.remote_server:app --host 127.0.0.1 --port 8020"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from agents import Agent, Runner
from fastapi import FastAPI
from pydantic import BaseModel

from agent_auth_sdk import AgentAuthRouter, AuthenticatedAgentContext, OpenAIAgentAuth
from agent_auth_sdk.integrations.openai_agents import OpenAIAgentsAuthConfig
from examples._shared import required_env, vault_verify_from_env

specialist = Agent(name="specialist", instructions="Return a concise answer to the authenticated request.")


class SpecialistRequest(BaseModel):
    question: str


class SpecialistResult(BaseModel):
    answer: str


def config() -> OpenAIAgentsAuthConfig:
    registry_url = required_env("AGENT_AUTH_REGISTRY_URL").rstrip("/")
    return OpenAIAgentsAuthConfig(
        roles=("specialist",),
        mode="vault",
        domain=required_env("AGENT_AUTH_AGENT_DOMAIN"),
        organization="Agent Auth OpenAI remote example",
        environment="production",
        runtime_dir=Path(".agent-auth/runtime-openai-server"),
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
        vault_key_names={"specialist": required_env("AGENT_AUTH_SPECIALIST_KEY_NAME")},
        auto_create_vault_keys=False,
    )


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("Set OPENAI_API_KEY before starting the remote server")
    auth = await OpenAIAgentAuth.from_config(config(), identity="specialist")
    router = AgentAuthRouter(auth)

    @router.agent_endpoint("/invoke", request_model=SpecialistRequest)
    async def invoke(
        context: AuthenticatedAgentContext,
        request: SpecialistRequest,
    ) -> SpecialistResult:
        result = await Runner.run(specialist, request.question, context=context)
        return SpecialistResult(answer=str(result.final_output))

    application.include_router(router.router)
    async with auth:
        yield


app = FastAPI(lifespan=lifespan)
