"""启动：uvicorn examples.remote_agent.receiver:app --host 127.0.0.1 --port 8010"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_auth_sdk import AgentAuthASGIMiddleware, AgentInstance, AgentVerifier, MetadataResolverConfig
from examples._shared import required_env, vault_verify_from_env

verifier = AgentVerifier(
    resolver_config=MetadataResolverConfig(
        registry_url=os.getenv("AGENT_AUTH_REGISTRY_URL", "https://registry.invalid"),
    ),
)
receiver: AgentInstance | None = None


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    global receiver
    domain = required_env("AGENT_AUTH_AGENT_DOMAIN")
    receiver = await asyncio.to_thread(
        AgentInstance.from_vault,
        domain=domain,
        name=os.getenv("AGENT_AUTH_RECEIVER_NAME", "quickstart/receiver"),
        organization="Agent Auth remote example",
        endpoint=required_env("AGENT_AUTH_RECEIVER_URL"),
        vault_addr=required_env("AGENT_AUTH_VAULT_ADDR"),
        vault_token_file=required_env("AGENT_AUTH_VAULT_TOKEN_FILE"),
        transit_mount=os.getenv("AGENT_AUTH_VAULT_TRANSIT_MOUNT", "transit"),
        key_name=required_env("AGENT_AUTH_RECEIVER_KEY_NAME"),
        namespace=os.getenv("AGENT_AUTH_VAULT_NAMESPACE") or None,
        verify=vault_verify_from_env(),
        environment="production",
    )
    await verifier.__aenter__()
    try:
        yield
    finally:
        await verifier.__aexit__()


application = FastAPI(lifespan=lifespan)


@application.post("/invoke")
async def invoke(request: Request) -> JSONResponse:
    if receiver is None:
        raise RuntimeError("receiver is not initialized")
    authenticated = request.state.agent_auth
    payload = await request.json()
    result = {"handled_by": receiver.agent_id, "input": payload}
    signed = await receiver.sign_message(
        payload=result,
        recipient=authenticated.agent_id,
        message_type="agent.call.result",
    )
    return JSONResponse(signed.model_dump(mode="json"))


app = AgentAuthASGIMiddleware(application, verifier=verifier)
