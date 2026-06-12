"""中心注册服务器：统一接收开发者发布的 Agent metadata。"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agent_auth_sdk.models import AgentMetadata, AgentRegistryDocument, AgentRegistryEntry


class PublishRequest(BaseModel):
    agent_id: str
    metadata: AgentMetadata
    publisher: str | None = None


def load_registry_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_PATH", "runtime/registry/.well-known/agent.json"))


def load_registry_token() -> str | None:
    return os.getenv("AGENT_REGISTRY_TOKEN")


def _read_registry(path: Path) -> AgentRegistryDocument:
    if not path.exists():
        return AgentRegistryDocument(updated_at=datetime.now(timezone.utc), agents=[])
    return AgentRegistryDocument.model_validate_json(path.read_text(encoding="utf-8"))


def _write_registry(path: Path, document: AgentRegistryDocument) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document.model_dump_json(indent=2), encoding="utf-8")


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Registry")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/agent.json")
    async def well_known_registry() -> JSONResponse:
        path = load_registry_path()
        document = _read_registry(path)
        return JSONResponse(document.model_dump(mode="json"))

    @app.post("/registry/agents")
    async def publish_agent(
        request: PublishRequest,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        expected_token = load_registry_token()
        if expected_token and authorization != f"Bearer {expected_token}":
            raise HTTPException(status_code=401, detail="invalid registry token")

        path = load_registry_path()
        document = _read_registry(path)
        remaining = [entry for entry in document.agents if entry.agent_id != request.agent_id]
        remaining.append(
            AgentRegistryEntry(
                agent_id=request.agent_id,
                metadata=request.metadata,
                published_at=datetime.now(timezone.utc),
                publisher=request.publisher,
            )
        )
        updated = AgentRegistryDocument(
            updated_at=datetime.now(timezone.utc),
            agents=sorted(remaining, key=lambda item: item.agent_id),
        )
        _write_registry(path, updated)
        return JSONResponse(
            {
                "ok": True,
                "agent_id": request.agent_id,
                "registry_path": str(path),
                "count": len(updated.agents),
            }
        )

    return app


app = create_app()
