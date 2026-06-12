"""真实软件示例：一个具备身份发布、验签、审计和 LLM 转发能力的网关。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agent_identity_sdk import (
    AgentAuditConfig,
    AgentKey,
    FileMetadataCache,
    GatewaySettings,
    InMemoryNonceStore,
    LocalPemSigner,
    VerificationConfig,
    build_agent_id,
    generate_ed25519_keypair,
    render_agent_metadata,
    verify_http_request,
)
from agent_identity_sdk.config import TEST_PROFILE, get_runtime_profile
from agent_identity_sdk.crypto import public_key_to_base64url

from .audit import AuditStore
from .llm_client import OpenAICompatClient


class InvokeRequest(BaseModel):
    messages: list[dict] = Field(default_factory=list)
    model: str = "gpt-4o-mini"
    temperature: float = 0.2
    metadata: dict | None = None


def load_settings() -> GatewaySettings:
    profile_name = os.getenv("AGENT_PROFILE", "test")
    settings = GatewaySettings(
        host=os.getenv("AGENT_GATEWAY_HOST", "0.0.0.0"),
        port=int(os.getenv("AGENT_GATEWAY_PORT", "8010")),
        agent_host=os.getenv("AGENT_GATEWAY_AGENT_HOST", "192.144.228.237:8010"),
        agent_name=os.getenv("AGENT_GATEWAY_AGENT_NAME", "llm-gateway"),
        organization=os.getenv("AGENT_GATEWAY_ORG", "Demo Org"),
        profile=get_runtime_profile(profile_name),
        audit_path=Path(os.getenv("AGENT_GATEWAY_AUDIT_PATH", "runtime/audit.sqlite3")),
        metadata_dir=Path(os.getenv("AGENT_GATEWAY_METADATA_DIR", "runtime/well-known")),
        private_key_path=Path(os.getenv("AGENT_GATEWAY_PRIVATE_KEY", "runtime/keys/private_key.pem")),
        public_key_path=Path(os.getenv("AGENT_GATEWAY_PUBLIC_KEY", "runtime/keys/public_key.pem")),
        public_key_base64url_path=Path(os.getenv("AGENT_GATEWAY_PUBLIC_KEY_B64", "runtime/keys/public_key.base64url")),
        kid=os.getenv("AGENT_GATEWAY_KID", "main"),
        llm_base_url=os.getenv("AGENT_GATEWAY_LLM_BASE_URL", "https://yunwu.ai/"),
        llm_api_key=os.getenv("AGENT_GATEWAY_LLM_API_KEY"),
        llm_model=os.getenv("AGENT_GATEWAY_LLM_MODEL", "gpt-4o-mini"),
        llm_timeout_seconds=float(os.getenv("AGENT_GATEWAY_LLM_TIMEOUT", "30")),
    )
    return settings


def ensure_runtime_files(settings: GatewaySettings) -> None:
    settings.private_key_path.parent.mkdir(parents=True, exist_ok=True)
    settings.metadata_dir.mkdir(parents=True, exist_ok=True)
    if not settings.private_key_path.exists() or not settings.public_key_path.exists():
        pair = generate_ed25519_keypair(kid=settings.kid)
        settings.private_key_path.write_text(pair.private_key_pem, encoding="utf-8")
        settings.public_key_path.write_text(pair.public_key_pem, encoding="utf-8")
        settings.public_key_base64url_path.write_text(pair.public_key_base64url, encoding="utf-8")
    public_key_pem = settings.public_key_path.read_text(encoding="utf-8")
    metadata = render_agent_metadata(
        agent_id=build_agent_id(settings.agent_host, settings.agent_name),
        domain=settings.agent_host,
        name=settings.agent_name,
        organization=settings.organization,
        endpoint=_endpoint_url(settings),
        capabilities=["agent-auth", "llm-gateway", "openai-compatible"],
        keys=[
            AgentKey(
                kid=settings.kid,
                public_key_pem=public_key_pem,
                public_key_base64url=public_key_to_base64url(public_key_pem),
                status="active",
            )
        ],
        environment=settings.profile.name,
        signing_policy={"canonical_request": "v1"},
        verification_policy={"profile": settings.profile.name},
        audit=AgentAuditConfig(mode="sqlite", destination=str(settings.audit_path)),
    )
    target_dir = settings.metadata_dir / ".well-known"
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "agent.json").write_text(
        metadata.model_dump_json(indent=2),
        encoding="utf-8",
    )


def _endpoint_url(settings: GatewaySettings) -> str:
    scheme = "http" if settings.profile.allow_http else "https"
    return f"{scheme}://{settings.agent_host}/invoke"


def create_app(
    settings: GatewaySettings | None = None,
    *,
    llm_client: OpenAICompatClient | None = None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    ensure_runtime_files(settings)

    app = FastAPI(title="LLM Agent Gateway")
    audit_store = AuditStore(settings.audit_path)
    nonce_store = InMemoryNonceStore()
    metadata_cache = FileMetadataCache("runtime/metadata_cache.sqlite3")
    resolved_llm_client = llm_client
    if resolved_llm_client is None and settings.llm_api_key:
        resolved_llm_client = OpenAICompatClient(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            timeout_seconds=settings.llm_timeout_seconds,
        )
    resolved_http_client_factory = http_client_factory or (lambda: httpx.AsyncClient())

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "profile": settings.profile.name}

    @app.get("/.well-known/agent.json")
    async def well_known() -> JSONResponse:
        agent_json = json.loads((settings.metadata_dir / ".well-known" / "agent.json").read_text(encoding="utf-8"))
        return JSONResponse(agent_json)

    @app.get("/audit/recent")
    async def recent(limit: int = 20) -> list[dict]:
        return audit_store.recent(limit)

    @app.post("/invoke")
    async def invoke(request: Request, payload: InvokeRequest) -> JSONResponse:
        request_id = str(uuid4())
        headers = {key: value for key, value in request.headers.items()}
        raw_body = await request.body()
        normalized_payload = payload.model_dump(mode="json", exclude_none=True)
        async with resolved_http_client_factory() as client:
            verification = await verify_http_request(
                method=request.method,
                url=str(request.url).replace("http://", f"{'http' if settings.profile.allow_http else 'https'}://"),
                headers=headers,
                body=raw_body,
                nonce_store=nonce_store,
                http_client=client,
                cache=metadata_cache,
                config=VerificationConfig(profile=settings.profile),
                request_id=request_id,
            )

        if not verification.ok:
            audit_store.log(
                request_id=request_id,
                agent_id=headers.get("x-agent-id"),
                kid=headers.get("x-agent-kid"),
                verification_result=verification.code,
                llm_model=payload.model,
                payload={"request": normalized_payload, "reason": verification.reason},
            )
            raise HTTPException(status_code=401, detail={"ok": False, "code": verification.code, "reason": verification.reason})

        if resolved_llm_client is None:
            llm_response = {
                "id": "mock-response",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "LLM API 未配置，当前返回本地 mock 响应。",
                        }
                    }
                ],
            }
        else:
            llm_response = await resolved_llm_client.chat(
                messages=payload.messages,
                model=payload.model or settings.llm_model,
                temperature=payload.temperature,
            )

        audit_store.log(
            request_id=request_id,
            agent_id=verification.agent_id,
            kid=verification.kid,
            verification_result="ok",
            llm_model=payload.model,
            payload={"request": normalized_payload, "response": llm_response},
        )
        return JSONResponse(
            {
                "verified_agent": verification.agent_id,
                "verification_kid": verification.kid,
                "request_id": request_id,
                "llm_response": llm_response,
                "audit_ref": request_id,
            }
        )

    return app


app = create_app()
