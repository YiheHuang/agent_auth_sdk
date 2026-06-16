"""中心注册服务器：安全接收开发者发布的 Agent metadata。"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agent_auth_sdk.identity import build_agent_id
from agent_auth_sdk.models import AgentKey, AgentMetadata
from agent_auth_sdk.registry_security import (
    agent_key_fingerprint,
    hash_api_key,
    is_legacy_api_key_hash,
    verify_api_key,
    verify_registry_new_key_proof,
    verify_registry_publish_signature,
)

from .storage import RegistryStore


class PublishRequest(BaseModel):
    agent_id: str
    metadata: AgentMetadata
    publish_intent: str


class RotateKeyRequest(BaseModel):
    agent_id: str
    new_key: AgentKey
    new_key_proof_headers: dict[str, str]


def load_registry_public_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_PATH", "runtime/registry/.well-known/agent.json"))


def load_registry_db_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_DB_PATH", "runtime/registry/registry.sqlite3"))


def load_registry_allowed_skew_seconds() -> int:
    return int(os.getenv("AGENT_REGISTRY_ALLOWED_SKEW_SECONDS", "300"))


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Registry")
    store = RegistryStore(load_registry_db_path())

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/agent.json")
    async def well_known_registry() -> JSONResponse:
        public_path = load_registry_public_path()
        store.write_public_document(public_path)
        return JSONResponse(store.render_public_document().model_dump(mode="json"))

    @app.post("/registry/agents/publish")
    async def publish_agent(
        request: PublishRequest,
        http_request: Request,
        authorization: str | None = Header(default=None),
        x_agent_id: str | None = Header(default=None),
        x_agent_kid: str | None = Header(default=None),
        x_agent_timestamp: str | None = Header(default=None),
        x_agent_nonce: str | None = Header(default=None),
        x_agent_signature: str | None = Header(default=None),
        x_registry_client_id: str | None = Header(default=None),
    ) -> JSONResponse:
        source_ip = http_request.client.host if http_request.client else None
        developer = _authenticate_developer(store, authorization, x_registry_client_id)
        try:
            _validate_publish_headers(
                request=request,
                x_agent_id=x_agent_id,
                x_agent_kid=x_agent_kid,
                x_agent_timestamp=x_agent_timestamp,
                x_agent_nonce=x_agent_nonce,
                x_agent_signature=x_agent_signature,
            )
            _assert_fresh_timestamp(x_agent_timestamp)
            nonce_key = f"{developer.developer_id}:{x_agent_nonce}"
            if store.has_nonce(nonce_key):
                raise HTTPException(status_code=409, detail="NONCE_REPLAYED")

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                _validate_new_agent_identity(request.metadata)
                signing_key = _select_key(request.metadata.keys, x_agent_kid)
                verified = verify_registry_publish_signature(
                    path="/registry/agents/publish",
                    host=http_request.headers.get("host", ""),
                    body=request.model_dump(mode="json"),
                    headers=dict(http_request.headers),
                    public_key=signing_key,
                )
                if not verified:
                    raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
                store.upsert_agent(
                    metadata=request.metadata,
                    developer_id=developer.developer_id,
                    current_kid=x_agent_kid,
                    public_key_fingerprint=agent_key_fingerprint(signing_key),
                )
            else:
                if ownership.owner_developer_id != developer.developer_id:
                    raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
                entry = store.get_registry_entry(request.agent_id)
                if entry is None:
                    raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
                current_metadata = AgentMetadata.model_validate_json(entry.metadata_json)
                _validate_immutable_fields(current_metadata, request.metadata)
                if _keys_changed(current_metadata.keys, request.metadata.keys):
                    raise HTTPException(status_code=409, detail="KEY_CHANGE_REQUIRES_ROTATION")
                signing_key = _select_key(current_metadata.keys, x_agent_kid)
                verified = verify_registry_publish_signature(
                    path="/registry/agents/publish",
                    host=http_request.headers.get("host", ""),
                    body=request.model_dump(mode="json"),
                    headers=dict(http_request.headers),
                    public_key=signing_key,
                )
                if not verified:
                    raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
                store.upsert_agent(
                    metadata=request.metadata,
                    developer_id=developer.developer_id,
                    current_kid=ownership.current_kid,
                    public_key_fingerprint=ownership.public_key_fingerprint,
                    created_at=ownership.created_at,
                )

            store.set_nonce(nonce_key, datetime.now(timezone.utc) + timedelta(seconds=load_registry_allowed_skew_seconds()))
            store.write_public_document(load_registry_public_path())
            store.write_audit(
                developer_id=developer.developer_id,
                agent_id=request.agent_id,
                action="publish",
                result="success",
                reason_code=None,
                source_ip=source_ip,
            )
            return JSONResponse(
                {
                    "ok": True,
                    "agent_id": request.agent_id,
                    "developer_id": developer.developer_id,
                    "client_id": developer.client_id,
                },
            )
        except HTTPException as exc:
            store.write_audit(
                developer_id=getattr(developer, "developer_id", None),
                agent_id=request.agent_id,
                action="publish",
                result="rejected",
                reason_code=str(exc.detail),
                source_ip=source_ip,
            )
            raise

    @app.post("/registry/agents/rotate-key")
    async def rotate_key(
        request: RotateKeyRequest,
        http_request: Request,
        authorization: str | None = Header(default=None),
        x_agent_id: str | None = Header(default=None),
        x_agent_kid: str | None = Header(default=None),
        x_agent_timestamp: str | None = Header(default=None),
        x_agent_nonce: str | None = Header(default=None),
        x_agent_signature: str | None = Header(default=None),
        x_registry_client_id: str | None = Header(default=None),
    ) -> JSONResponse:
        source_ip = http_request.client.host if http_request.client else None
        developer = _authenticate_developer(store, authorization, x_registry_client_id)
        try:
            if x_agent_id != request.agent_id:
                raise HTTPException(status_code=400, detail="AGENT_ID_MISMATCH")
            _assert_fresh_timestamp(x_agent_timestamp)
            nonce_key = f"{developer.developer_id}:{x_agent_nonce}"
            if store.has_nonce(nonce_key):
                raise HTTPException(status_code=409, detail="NONCE_REPLAYED")
            proof_headers = request.new_key_proof_headers
            if not proof_headers:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_REQUIRED")
            normalized_proof_headers = {key.lower(): value for key, value in proof_headers.items()}
            _assert_fresh_timestamp(normalized_proof_headers.get("x-agent-timestamp"))
            proof_nonce = normalized_proof_headers.get("x-agent-nonce")
            if not proof_nonce:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_MISSING_NONCE")
            proof_nonce_key = f"{developer.developer_id}:new-key:{proof_nonce}"
            if store.has_nonce(proof_nonce_key):
                raise HTTPException(status_code=409, detail="NEW_KEY_PROOF_NONCE_REPLAYED")

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
            if ownership.owner_developer_id != developer.developer_id:
                raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
            entry = store.get_registry_entry(request.agent_id)
            if entry is None:
                raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
            metadata = AgentMetadata.model_validate_json(entry.metadata_json)
            old_key = _select_key(metadata.keys, x_agent_kid)
            verified = verify_registry_publish_signature(
                path="/registry/agents/rotate-key",
                host=http_request.headers.get("host", ""),
                body=request.model_dump(mode="json"),
                headers=dict(http_request.headers),
                public_key=old_key,
            )
            if not verified:
                raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
            proof_valid = verify_registry_new_key_proof(
                agent_id=request.agent_id,
                new_key=request.new_key,
                headers=proof_headers,
                host=http_request.headers.get("host", ""),
            )
            if not proof_valid:
                raise HTTPException(status_code=401, detail="NEW_KEY_PROOF_INVALID")

            updated_keys = []
            for key in metadata.keys:
                if key.kid == x_agent_kid:
                    updated_keys.append(key.model_copy(update={"status": "inactive"}))
                else:
                    updated_keys.append(key)
            updated_keys.append(request.new_key.model_copy(update={"status": "active"}))
            updated_metadata = metadata.model_copy(
                update={
                    "keys": updated_keys,
                    "updated_at": datetime.now(timezone.utc),
                },
            )
            store.upsert_agent(
                metadata=updated_metadata,
                developer_id=developer.developer_id,
                current_kid=request.new_key.kid,
                public_key_fingerprint=agent_key_fingerprint(request.new_key),
                created_at=ownership.created_at,
            )
            store.set_nonce(nonce_key, datetime.now(timezone.utc) + timedelta(seconds=load_registry_allowed_skew_seconds()))
            store.set_nonce(proof_nonce_key, datetime.now(timezone.utc) + timedelta(seconds=load_registry_allowed_skew_seconds()))
            store.write_public_document(load_registry_public_path())
            store.write_audit(
                developer_id=developer.developer_id,
                agent_id=request.agent_id,
                action="rotate_key",
                result="success",
                reason_code=None,
                source_ip=source_ip,
            )
            return JSONResponse({"ok": True, "agent_id": request.agent_id, "current_kid": request.new_key.kid})
        except HTTPException as exc:
            store.write_audit(
                developer_id=getattr(developer, "developer_id", None),
                agent_id=request.agent_id,
                action="rotate_key",
                result="rejected",
                reason_code=str(exc.detail),
                source_ip=source_ip,
            )
            raise

    return app


def _authenticate_developer(store: RegistryStore, authorization: str | None, client_id: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="MISSING_DEVELOPER_API_KEY")
    if not client_id:
        raise HTTPException(status_code=401, detail="MISSING_CLIENT_ID")
    developer = store.get_developer_by_client_id(client_id)
    if developer is None or developer.status != "active":
        raise HTTPException(status_code=401, detail="DEVELOPER_NOT_FOUND")
    api_key = authorization.removeprefix("Bearer ").strip()
    if not verify_api_key(api_key, developer.api_key_hash):
        raise HTTPException(status_code=401, detail="INVALID_DEVELOPER_API_KEY")
    if is_legacy_api_key_hash(developer.api_key_hash):
        store.update_developer_api_key_hash(client_id=client_id, api_key_hash=hash_api_key(api_key))
    return developer


def _validate_publish_headers(
    *,
    request: PublishRequest,
    x_agent_id: str | None,
    x_agent_kid: str | None,
    x_agent_timestamp: str | None,
    x_agent_nonce: str | None,
    x_agent_signature: str | None,
) -> None:
    if request.publish_intent != "upsert_metadata":
        raise HTTPException(status_code=400, detail="INVALID_PUBLISH_INTENT")
    if x_agent_id != request.agent_id:
        raise HTTPException(status_code=400, detail="AGENT_ID_MISMATCH")
    if not x_agent_kid:
        raise HTTPException(status_code=400, detail="MISSING_AGENT_KID")
    if not x_agent_timestamp:
        raise HTTPException(status_code=400, detail="MISSING_TIMESTAMP")
    if not x_agent_nonce:
        raise HTTPException(status_code=400, detail="MISSING_NONCE")
    if not x_agent_signature:
        raise HTTPException(status_code=400, detail="MISSING_SIGNATURE")


def _assert_fresh_timestamp(value: str | None) -> None:
    if not value:
        raise HTTPException(status_code=400, detail="MISSING_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="INVALID_TIMESTAMP") from exc
    skew = abs((datetime.now(timezone.utc) - parsed).total_seconds())
    if skew > load_registry_allowed_skew_seconds():
        raise HTTPException(status_code=401, detail="TIMESTAMP_EXPIRED")


def _validate_new_agent_identity(metadata: AgentMetadata) -> None:
    expected_agent_id = build_agent_id(metadata.domain, metadata.name)
    if metadata.agent_id != expected_agent_id:
        raise HTTPException(status_code=400, detail="AGENT_ID_SUBJECT_MISMATCH")


def _validate_immutable_fields(current: AgentMetadata, incoming: AgentMetadata) -> None:
    if current.agent_id != incoming.agent_id:
        raise HTTPException(status_code=409, detail="IMMUTABLE_AGENT_ID")
    if current.domain != incoming.domain:
        raise HTTPException(status_code=409, detail="IMMUTABLE_DOMAIN")
    if current.name != incoming.name:
        raise HTTPException(status_code=409, detail="IMMUTABLE_NAME")


def _select_key(keys: list[AgentKey], kid: str | None) -> AgentKey:
    for key in keys:
        if key.kid == kid and key.status == "active":
            return key
    raise HTTPException(status_code=401, detail="ACTIVE_KEY_NOT_FOUND")


def _keys_changed(current: list[AgentKey], incoming: list[AgentKey]) -> bool:
    current_payload = [key.model_dump(mode="json") for key in current]
    incoming_payload = [key.model_dump(mode="json") for key in incoming]
    return current_payload != incoming_payload


app = create_app()
