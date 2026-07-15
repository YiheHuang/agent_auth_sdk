"""中心注册服务器：安全接收开发者发布的 Agent metadata。"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from agent_auth_sdk.http_utils import parse_rfc3339_utc_seconds
from agent_auth_sdk.identity import assert_strict_agent_id, build_agent_id, parse_agent_id
from agent_auth_sdk.models import AgentKey, AgentMetadata
from agent_auth_sdk.registry_security import (
    agent_key_fingerprint,
    hash_api_key,
    is_legacy_api_key_hash,
    verify_api_key,
    verify_registry_add_key_proof,
    verify_registry_new_key_proof,
    verify_registry_publish_signature,
)

from .storage import AgentStateConflictError, OwnershipRecord, RegistryStore


class PublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    metadata: AgentMetadata
    publish_intent: str


class RotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    new_key: AgentKey
    new_key_proof_headers: dict[str, str]


class AddKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    new_key: AgentKey
    new_key_proof_headers: dict[str, str]


class RevokeKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    kid_to_revoke: str


class RevokeAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str


def load_registry_public_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_PATH", "runtime/registry/.well-known/agent.json"))


def load_registry_db_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_DB_PATH", "runtime/registry/registry.sqlite3"))


def load_registry_allowed_skew_seconds() -> int:
    return int(os.getenv("AGENT_REGISTRY_ALLOWED_SKEW_SECONDS", "300"))


def load_registry_strict_identities() -> bool:
    return os.getenv("AGENT_REGISTRY_STRICT_IDENTITIES", "1").strip().lower() not in {"0", "false", "no", "off"}


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Registry")
    store = RegistryStore(load_registry_db_path())

    @app.middleware("http")
    async def legacy_route_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        if request.url.path.startswith("/registry/agents/"):
            successor = request.url.path.replace("/registry/agents/", "/v1/agents/", 1)
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = "Thu, 01 Jul 2027 00:00:00 GMT"
            response.headers["Link"] = f'<{successor}>; rel="successor-version"'
        return response

    @app.get("/health/live")
    def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def health_ready() -> JSONResponse:
        ready = store.readiness_check()
        return JSONResponse(
            {"status": "ok" if ready else "not_ready"},
            status_code=200 if ready else 503,
        )

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return health_ready()

    @app.get("/.well-known/agent.json")
    def well_known_registry() -> JSONResponse:
        document = store.render_public_document()
        payload = document.model_dump(mode="json")
        etag = hashlib.sha256(document.model_dump_json().encode("utf-8")).hexdigest()
        return JSONResponse(payload, headers={"ETag": f'"{etag}"', "Cache-Control": "public, max-age=60"})

    @app.get("/v1/agents/resolve")
    def resolve_registry_agent(agent_id: str) -> JSONResponse:
        try:
            parse_agent_id(agent_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="INVALID_AGENT_ID") from exc
        ownership = store.get_ownership(agent_id)
        entry = store.get_registry_entry(agent_id)
        if ownership is None or ownership.status != "active" or entry is None:
            raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
        metadata = AgentMetadata.model_validate_json(entry.metadata_json)
        etag = hashlib.sha256(entry.metadata_json.encode("utf-8")).hexdigest()
        return JSONResponse(
            {"agent_id": agent_id, "metadata": metadata.model_dump(mode="json")},
            headers={"ETag": f'"{etag}"', "Cache-Control": "public, max-age=60"},
        )

    @app.post("/v1/agents/publish")
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
        developer = None
        try:
            developer = _authenticate_developer(store, authorization, x_registry_client_id)
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

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                _assert_developer_namespace(store, developer.developer_id, request.agent_id)
                _validate_new_agent_identity(request)
                signing_key = _select_key(request.metadata.keys, x_agent_kid)
                verified = verify_registry_publish_signature(
                    path=http_request.url.path,
                    host=http_request.headers.get("host", ""),
                    body=await http_request.body(),
                    headers=dict(http_request.headers),
                    public_key=signing_key,
                )
                if not verified:
                    raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
                try:
                    committed = store.commit_agent_operation(
                        metadata=request.metadata,
                        developer_id=developer.developer_id,
                        current_kid=x_agent_kid,
                        public_key_fingerprint=agent_key_fingerprint(signing_key),
                        nonce_keys=[nonce_key],
                        nonce_expires_at=_registry_nonce_expiry(),
                        action="publish",
                        source_ip=source_ip,
                        create=True,
                    )
                except sqlite3.IntegrityError as exc:
                    raise HTTPException(status_code=409, detail="AGENT_ALREADY_EXISTS") from exc
                if not committed:
                    raise HTTPException(status_code=409, detail="NONCE_REPLAYED")
            else:
                if ownership.owner_developer_id != developer.developer_id:
                    raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
                _assert_developer_namespace(store, developer.developer_id, request.agent_id)
                _assert_agent_active(ownership)
                entry = store.get_registry_entry(request.agent_id)
                if entry is None:
                    raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
                current_metadata = AgentMetadata.model_validate_json(entry.metadata_json)
                _validate_immutable_fields(current_metadata, request.metadata)
                if _keys_changed(current_metadata.keys, request.metadata.keys):
                    raise HTTPException(status_code=409, detail="KEY_CHANGE_REQUIRES_ROTATION")
                signing_key = _select_key(current_metadata.keys, x_agent_kid)
                verified = verify_registry_publish_signature(
                    path=http_request.url.path,
                    host=http_request.headers.get("host", ""),
                    body=await http_request.body(),
                    headers=dict(http_request.headers),
                    public_key=signing_key,
                )
                if not verified:
                    raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
                try:
                    committed = store.commit_agent_operation(
                        metadata=request.metadata,
                        developer_id=developer.developer_id,
                        current_kid=ownership.current_kid,
                        public_key_fingerprint=ownership.public_key_fingerprint,
                        created_at=ownership.created_at,
                        expected_updated_at=ownership.updated_at,
                        nonce_keys=[nonce_key],
                        nonce_expires_at=_registry_nonce_expiry(),
                        action="publish",
                        source_ip=source_ip,
                        create=False,
                    )
                except AgentStateConflictError as exc:
                    raise HTTPException(status_code=409, detail="AGENT_STATE_CONFLICT") from exc
                if not committed:
                    raise HTTPException(status_code=409, detail="NONCE_REPLAYED")

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

    @app.post("/v1/agents/rotate-key")
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
        developer = None
        try:
            developer = _authenticate_developer(store, authorization, x_registry_client_id)
            if x_agent_id != request.agent_id:
                raise HTTPException(status_code=400, detail="AGENT_ID_MISMATCH")
            _assert_fresh_timestamp(x_agent_timestamp)
            nonce_key = f"{developer.developer_id}:{x_agent_nonce}"
            proof_headers = request.new_key_proof_headers
            if not proof_headers:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_REQUIRED")
            normalized_proof_headers = {key.lower(): value for key, value in proof_headers.items()}
            _assert_fresh_timestamp(normalized_proof_headers.get("x-agent-timestamp"))
            proof_nonce = normalized_proof_headers.get("x-agent-nonce")
            if not proof_nonce:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_MISSING_NONCE")
            proof_nonce_key = f"{developer.developer_id}:new-key:{proof_nonce}"
            if normalized_proof_headers.get("x-registry-client-id") != developer.client_id:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_CLIENT_MISMATCH")

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
            if ownership.owner_developer_id != developer.developer_id:
                raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
            _assert_developer_namespace(store, developer.developer_id, request.agent_id)
            _assert_agent_active(ownership)
            if x_agent_kid != ownership.current_kid:
                raise HTTPException(status_code=409, detail="ROTATION_REQUIRES_CURRENT_KEY")
            entry = store.get_registry_entry(request.agent_id)
            if entry is None:
                raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
            metadata = AgentMetadata.model_validate_json(entry.metadata_json)
            if (
                request.new_key.kid in {key.kid for key in metadata.keys}
                or request.new_key.kid in metadata.revoked_kids
            ):
                raise HTTPException(status_code=409, detail="KID_ALREADY_USED")
            old_key = _select_key(metadata.keys, x_agent_kid)
            verified = verify_registry_publish_signature(
                path=http_request.url.path,
                host=http_request.headers.get("host", ""),
                body=await http_request.body(),
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
                    "updated_at": datetime.now(UTC),
                },
            )
            try:
                committed = store.commit_agent_operation(
                    metadata=updated_metadata,
                    developer_id=developer.developer_id,
                    current_kid=request.new_key.kid,
                    public_key_fingerprint=agent_key_fingerprint(request.new_key),
                    created_at=ownership.created_at,
                    expected_updated_at=ownership.updated_at,
                    nonce_keys=[nonce_key, proof_nonce_key],
                    nonce_expires_at=_registry_nonce_expiry(),
                    action="rotate_key",
                    source_ip=source_ip,
                    create=False,
                )
            except AgentStateConflictError as exc:
                raise HTTPException(status_code=409, detail="AGENT_STATE_CONFLICT") from exc
            if not committed:
                raise HTTPException(status_code=409, detail="NONCE_REPLAYED")
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

    @app.post("/v1/agents/add-key")
    @app.post("/registry/agents/add-key")
    async def add_key(
        request: AddKeyRequest,
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
        developer = None
        try:
            developer = _authenticate_developer(store, authorization, x_registry_client_id)
            if x_agent_id != request.agent_id:
                raise HTTPException(status_code=400, detail="AGENT_ID_MISMATCH")
            _assert_fresh_timestamp(x_agent_timestamp)
            nonce_key = f"{developer.developer_id}:{x_agent_nonce}"
            proof_headers = request.new_key_proof_headers
            if not proof_headers:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_REQUIRED")
            normalized_proof_headers = {key.lower(): value for key, value in proof_headers.items()}
            _assert_fresh_timestamp(normalized_proof_headers.get("x-agent-timestamp"))
            proof_nonce = normalized_proof_headers.get("x-agent-nonce")
            if not proof_nonce:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_MISSING_NONCE")
            proof_nonce_key = f"{developer.developer_id}:add-key:{proof_nonce}"
            if normalized_proof_headers.get("x-registry-client-id") != developer.client_id:
                raise HTTPException(status_code=400, detail="NEW_KEY_PROOF_CLIENT_MISMATCH")

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
            if ownership.owner_developer_id != developer.developer_id:
                raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
            _assert_developer_namespace(store, developer.developer_id, request.agent_id)
            _assert_agent_active(ownership)
            entry = store.get_registry_entry(request.agent_id)
            if entry is None:
                raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
            metadata = AgentMetadata.model_validate_json(entry.metadata_json)
            if (
                request.new_key.kid in {key.kid for key in metadata.keys}
                or request.new_key.kid in metadata.revoked_kids
            ):
                raise HTTPException(status_code=409, detail="KID_ALREADY_USED")
            old_key = _select_key(metadata.keys, x_agent_kid)
            verified = verify_registry_publish_signature(
                path=http_request.url.path,
                host=http_request.headers.get("host", ""),
                body=await http_request.body(),
                headers=dict(http_request.headers),
                public_key=old_key,
            )
            if not verified:
                raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
            proof_valid = verify_registry_add_key_proof(
                agent_id=request.agent_id,
                new_key=request.new_key,
                headers=proof_headers,
                host=http_request.headers.get("host", ""),
            )
            if not proof_valid:
                raise HTTPException(status_code=401, detail="NEW_KEY_PROOF_INVALID")

            # 追加新 key，不修改已有 key 状态
            updated_keys = [*metadata.keys, request.new_key.model_copy(update={"status": "active"})]
            updated_metadata = metadata.model_copy(
                update={
                    "keys": updated_keys,
                    "updated_at": datetime.now(UTC),
                },
            )
            try:
                committed = store.commit_agent_operation(
                    metadata=updated_metadata,
                    developer_id=developer.developer_id,
                    current_kid=ownership.current_kid,
                    public_key_fingerprint=ownership.public_key_fingerprint,
                    created_at=ownership.created_at,
                    expected_updated_at=ownership.updated_at,
                    nonce_keys=[nonce_key, proof_nonce_key],
                    nonce_expires_at=_registry_nonce_expiry(),
                    action="add_key",
                    source_ip=source_ip,
                    create=False,
                )
            except AgentStateConflictError as exc:
                raise HTTPException(status_code=409, detail="AGENT_STATE_CONFLICT") from exc
            if not committed:
                raise HTTPException(status_code=409, detail="NONCE_REPLAYED")
            return JSONResponse({"ok": True, "agent_id": request.agent_id, "added_kid": request.new_key.kid})
        except HTTPException as exc:
            store.write_audit(
                developer_id=getattr(developer, "developer_id", None),
                agent_id=request.agent_id,
                action="add_key",
                result="rejected",
                reason_code=str(exc.detail),
                source_ip=source_ip,
            )
            raise

    @app.post("/v1/agents/revoke-key")
    @app.post("/registry/agents/revoke-key")
    async def revoke_key(
        request: RevokeKeyRequest,
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
        developer = None
        try:
            developer = _authenticate_developer(store, authorization, x_registry_client_id)
            if x_agent_id != request.agent_id:
                raise HTTPException(status_code=400, detail="AGENT_ID_MISMATCH")
            _assert_fresh_timestamp(x_agent_timestamp)
            nonce_key = f"{developer.developer_id}:{x_agent_nonce}"

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
            if ownership.owner_developer_id != developer.developer_id:
                raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
            _assert_developer_namespace(store, developer.developer_id, request.agent_id)
            _assert_agent_active(ownership)
            if x_agent_kid != ownership.current_kid:
                raise HTTPException(status_code=409, detail="OPERATION_REQUIRES_CURRENT_KEY")
            entry = store.get_registry_entry(request.agent_id)
            if entry is None:
                raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
            metadata = AgentMetadata.model_validate_json(entry.metadata_json)
            old_key = _select_key(metadata.keys, x_agent_kid)
            verified = verify_registry_publish_signature(
                path=http_request.url.path,
                host=http_request.headers.get("host", ""),
                body=await http_request.body(),
                headers=dict(http_request.headers),
                public_key=old_key,
            )
            if not verified:
                raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")

            # 校验 kid_to_revoke 存在
            target_key = None
            active_count = 0
            for key in metadata.keys:
                if key.kid == request.kid_to_revoke:
                    target_key = key
                if key.status == "active":
                    active_count += 1
            if target_key is None:
                raise HTTPException(status_code=400, detail="KEY_NOT_FOUND")
            if request.kid_to_revoke == ownership.current_kid:
                raise HTTPException(status_code=409, detail="CANNOT_REVOKE_CURRENT_KEY")
            if target_key.status == "revoked" or request.kid_to_revoke in metadata.revoked_kids:
                raise HTTPException(status_code=409, detail="KEY_ALREADY_REVOKED")
            # 防锁死：不能撤销唯一的 active key
            if target_key.status == "active" and active_count <= 1:
                raise HTTPException(status_code=409, detail="CANNOT_REVOKE_LAST_ACTIVE_KEY")

            # 加入 revoked_kids + 标记 status="revoked"
            updated_revoked = [*metadata.revoked_kids, request.kid_to_revoke]
            updated_keys = [
                key.model_copy(update={"status": "revoked"}) if key.kid == request.kid_to_revoke else key
                for key in metadata.keys
            ]
            updated_metadata = metadata.model_copy(
                update={
                    "keys": updated_keys,
                    "revoked_kids": updated_revoked,
                    "updated_at": datetime.now(UTC),
                },
            )
            try:
                committed = store.commit_agent_operation(
                    metadata=updated_metadata,
                    developer_id=developer.developer_id,
                    current_kid=ownership.current_kid,
                    public_key_fingerprint=ownership.public_key_fingerprint,
                    created_at=ownership.created_at,
                    expected_updated_at=ownership.updated_at,
                    nonce_keys=[nonce_key],
                    nonce_expires_at=_registry_nonce_expiry(),
                    action="revoke_key",
                    source_ip=source_ip,
                    create=False,
                )
            except AgentStateConflictError as exc:
                raise HTTPException(status_code=409, detail="AGENT_STATE_CONFLICT") from exc
            if not committed:
                raise HTTPException(status_code=409, detail="NONCE_REPLAYED")
            return JSONResponse({"ok": True, "agent_id": request.agent_id, "revoked_kid": request.kid_to_revoke})
        except HTTPException as exc:
            store.write_audit(
                developer_id=getattr(developer, "developer_id", None),
                agent_id=request.agent_id,
                action="revoke_key",
                result="rejected",
                reason_code=str(exc.detail),
                source_ip=source_ip,
            )
            raise

    @app.post("/v1/agents/revoke")
    @app.post("/registry/agents/revoke")
    async def revoke_agent(
        request: RevokeAgentRequest,
        http_request: Request,
        authorization: str | None = Header(default=None),
        x_agent_id: str | None = Header(default=None),
        x_agent_kid: str | None = Header(default=None),
        x_agent_timestamp: str | None = Header(default=None),
        x_agent_nonce: str | None = Header(default=None),
        x_agent_signature: str | None = Header(default=None),
        x_registry_client_id: str | None = Header(default=None),
    ) -> JSONResponse:
        """撤销整个 Agent。撤销后 agent 从公开文档消失，所有操作被拒绝。"""
        source_ip = http_request.client.host if http_request.client else None
        developer = None
        try:
            developer = _authenticate_developer(store, authorization, x_registry_client_id)
            if x_agent_id != request.agent_id:
                raise HTTPException(status_code=400, detail="AGENT_ID_MISMATCH")
            if not x_agent_kid:
                raise HTTPException(status_code=400, detail="MISSING_AGENT_KID")
            _assert_fresh_timestamp(x_agent_timestamp)
            nonce_key = f"{developer.developer_id}:{x_agent_nonce}"

            ownership = store.get_ownership(request.agent_id)
            if ownership is None:
                raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
            _assert_agent_active(ownership)
            if ownership.owner_developer_id != developer.developer_id:
                raise HTTPException(status_code=403, detail="OWNER_MISMATCH")
            _assert_developer_namespace(store, developer.developer_id, request.agent_id)
            if x_agent_kid != ownership.current_kid:
                raise HTTPException(status_code=409, detail="OPERATION_REQUIRES_CURRENT_KEY")
            entry = store.get_registry_entry(request.agent_id)
            if entry is None:
                raise HTTPException(status_code=500, detail="REGISTRY_ENTRY_MISSING")
            metadata = AgentMetadata.model_validate_json(entry.metadata_json)
            old_key = _select_key(metadata.keys, x_agent_kid)
            verified = verify_registry_publish_signature(
                path=http_request.url.path,
                host=http_request.headers.get("host", ""),
                body=await http_request.body(),
                headers=dict(http_request.headers),
                public_key=old_key,
            )
            if not verified:
                raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")

            try:
                committed = store.commit_revoke_agent(
                    agent_id=request.agent_id,
                    developer_id=developer.developer_id,
                    nonce_key=nonce_key,
                    nonce_expires_at=_registry_nonce_expiry(),
                    source_ip=source_ip,
                    expected_current_kid=ownership.current_kid,
                    expected_updated_at=ownership.updated_at,
                )
            except AgentStateConflictError as exc:
                raise HTTPException(status_code=409, detail="AGENT_STATE_CONFLICT") from exc
            if not committed:
                raise HTTPException(status_code=409, detail="NONCE_REPLAYED")
            return JSONResponse({"ok": True, "agent_id": request.agent_id})
        except HTTPException as exc:
            store.write_audit(
                developer_id=getattr(developer, "developer_id", None),
                agent_id=request.agent_id,
                action="revoke_agent",
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


def _assert_agent_active(ownership: OwnershipRecord) -> None:
    if ownership.status != "active":
        raise HTTPException(status_code=410, detail="AGENT_REVOKED")


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
    if request.agent_id != request.metadata.agent_id:
        raise HTTPException(status_code=400, detail="METADATA_AGENT_ID_MISMATCH")
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
        parsed = parse_rfc3339_utc_seconds(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="INVALID_TIMESTAMP") from exc
    skew = abs((datetime.now(UTC) - parsed).total_seconds())
    if skew > load_registry_allowed_skew_seconds():
        raise HTTPException(status_code=401, detail="TIMESTAMP_EXPIRED")


def _validate_new_agent_identity(request: PublishRequest) -> None:
    metadata = request.metadata
    if load_registry_strict_identities():
        try:
            assert_strict_agent_id(request.agent_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="STRICT_AGENT_ID_REJECTED") from exc
    expected_agent_id = build_agent_id(metadata.domain, metadata.name)
    if request.agent_id != metadata.agent_id or metadata.agent_id != expected_agent_id:
        raise HTTPException(status_code=400, detail="AGENT_ID_SUBJECT_MISMATCH")
    active_keys = [key for key in metadata.keys if key.status == "active"]
    if not active_keys:
        raise HTTPException(status_code=400, detail="ACTIVE_KEY_REQUIRED")
    if any(key.kid in metadata.revoked_kids for key in active_keys):
        raise HTTPException(status_code=400, detail="ACTIVE_KEY_IS_REVOKED")


def _assert_developer_namespace(store: RegistryStore, developer_id: str, agent_id: str) -> None:
    try:
        parsed = parse_agent_id(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="INVALID_AGENT_ID") from exc
    agent_path = "/" + "/".join(parsed.path_segments)
    if not store.developer_has_namespace(
        developer_id=developer_id,
        domain=parsed.host,
        agent_path=agent_path,
    ):
        raise HTTPException(status_code=403, detail="NAMESPACE_NOT_AUTHORIZED")


def _registry_nonce_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=load_registry_allowed_skew_seconds())


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
