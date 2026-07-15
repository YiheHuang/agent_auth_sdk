"""远程 researcher Agent 服务。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from agent_auth import AgentAuth, AuthContext


class ResearchRequest(BaseModel):
    topic: str


class ResearchResult(BaseModel):
    summary: str


auth = AgentAuth()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    async with auth:
        yield


app = FastAPI(lifespan=lifespan)


@auth.endpoint("/invoke", identity="researcher", request=ResearchRequest, response=ResearchResult)
async def invoke(context: AuthContext, request: ResearchRequest) -> ResearchResult:
    return ResearchResult(summary=f"{context.sender} requested: {request.topic}")


app.include_router(auth.router)
