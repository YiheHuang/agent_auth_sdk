"""五路由中心 Registry。"""

from __future__ import annotations

import hashlib
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from agent_auth._errors import AgentAuthError
from agent_auth._identity import parse_agent_id, validate_endpoint, validate_service_url
from agent_auth._protocol import SignedEnvelope, parse_timestamp, verify_envelope
from agent_auth._types import AgentRecord

from .security import verify_api_key
from .storage import Developer, RegistryStore, StateConflictError


def load_db_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_DB_PATH", "runtime/registry.sqlite3"))


def load_registry_url() -> str:
    value = os.getenv("AGENT_REGISTRY_URL")
    if not value and strict_identities():
        raise RuntimeError("AGENT_REGISTRY_URL is required when strict identities are enabled")
    try:
        return validate_service_url(value or "http://testserver", strict=strict_identities())
    except AgentAuthError as exc:
        raise RuntimeError("AGENT_REGISTRY_URL must be a valid HTTPS public URL") from exc


def strict_identities() -> bool:
    return os.getenv("AGENT_REGISTRY_STRICT_IDENTITIES", "1").lower() not in {"0", "false", "no"}


def allowed_skew() -> int:
    return int(os.getenv("AGENT_REGISTRY_ALLOWED_SKEW_SECONDS", "120"))


def create_app(*, store: RegistryStore | None = None) -> FastAPI:
    load_registry_url()
    database = store or RegistryStore(load_db_path())
    app = FastAPI(
        title="Agent Auth Registry",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready() -> JSONResponse:
        ok = database.readiness()
        return JSONResponse({"status": "ok" if ok else "not_ready"}, status_code=200 if ok else 503)

    @app.get("/v1/agents/resolve")
    def resolve(agent_id: str, if_none_match: str | None = Header(default=None)) -> JSONResponse:
        try:
            parse_agent_id(agent_id, strict=strict_identities())
        except AgentAuthError as exc:
            raise HTTPException(status_code=400, detail=exc.code) from exc
        record = database.resolve(agent_id)
        if record is None:
            raise HTTPException(status_code=404, detail="AGENT_NOT_FOUND")
        payload = record.as_dict()
        etag = _etag(payload)
        if if_none_match == etag:
            return JSONResponse(content=None, status_code=304, headers={"ETag": etag})
        return JSONResponse(payload, headers={"ETag": etag, "Cache-Control": "public, max-age=60"})

    @app.get("/.well-known/agent.json")
    def well_known(if_none_match: str | None = Header(default=None)) -> JSONResponse:
        payload = {"version": 1, "agents": [record.as_dict() for record in database.list_active_agents()]}
        etag = _etag(payload)
        if if_none_match == etag:
            return JSONResponse(content=None, status_code=304, headers={"ETag": etag})
        return JSONResponse(payload, headers={"ETag": etag, "Cache-Control": "public, max-age=60"})

    @app.post("/v1/agents")
    async def mutate(
        request: Request,
        authorization: str | None = Header(default=None),
        x_registry_client_id: str | None = Header(default=None),
    ) -> JSONResponse:
        source_ip = request.client.host if request.client else None
        developer: Developer | None = None
        envelope: SignedEnvelope | None = None
        try:
            developer = _authenticate(database, authorization, x_registry_client_id)
            raw = await request.json()
            if not isinstance(raw, dict):
                raise AgentAuthError("ENVELOPE_INVALID", "Mutation body must be a signed envelope")
            envelope = SignedEnvelope.from_dict(raw)
            if database.has_nonce(envelope.sender, envelope.id):
                raise StateConflictError("NONCE_REPLAYED")
            if envelope.type == "registry.publish":
                record = _publish(database, developer, envelope)
                return JSONResponse({"ok": True, **record.as_dict()})
            if envelope.type == "registry.rotate":
                record = _rotate(database, developer, envelope)
                return JSONResponse({"ok": True, **record.as_dict()})
            if envelope.type == "registry.revoke":
                _revoke(database, developer, envelope)
                return JSONResponse({"ok": True, "agent_id": envelope.sender})
            raise AgentAuthError("MUTATION_TYPE_INVALID", "Unsupported Registry mutation type")
        except StateConflictError as exc:
            code = str(exc)
            database.write_audit(
                developer_id=developer.id if developer else None,
                agent_id=envelope.sender if envelope else None,
                action=envelope.type if envelope else "mutation",
                result="rejected",
                code=code,
                source_ip=source_ip,
            )
            status = 403 if code in {"OWNER_MISMATCH", "NAMESPACE_NOT_AUTHORIZED"} else 409
            raise HTTPException(status_code=status, detail=code) from exc
        except AgentAuthError as exc:
            database.write_audit(
                developer_id=developer.id if developer else None,
                agent_id=envelope.sender if envelope else None,
                action=envelope.type if envelope else "mutation",
                result="rejected",
                code=exc.code,
                source_ip=source_ip,
            )
            authentication_error = exc.code in {
                "SIGNATURE_INVALID",
                "TIMESTAMP_EXPIRED",
                "SIGNER_MISMATCH",
            }
            status = 401 if authentication_error else 400
            if exc.code in {"DEVELOPER_NOT_FOUND", "DEVELOPER_KEY_INVALID", "DEVELOPER_AUTH_MISSING"}:
                status = 401
            raise HTTPException(status_code=status, detail=exc.code) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="REQUEST_INVALID") from exc

    return app


def _publish(store: RegistryStore, developer: Developer, envelope: SignedEnvelope) -> AgentRecord:
    payload = _payload(envelope, {"agent_id", "endpoint", "capabilities", "kid", "public_key"})
    agent_id = _text(payload, "agent_id")
    endpoint = _text(payload, "endpoint")
    kid = _text(payload, "kid")
    public_key = _text(payload, "public_key")
    capabilities = payload["capabilities"]
    if not isinstance(capabilities, list) or not all(isinstance(value, str) for value in capabilities):
        raise AgentAuthError("METADATA_INVALID", "capabilities must be a string list")
    if envelope.sender != agent_id or envelope.kid != kid:
        raise AgentAuthError("SIGNER_MISMATCH", "Publish signer does not match metadata")
    parse_agent_id(agent_id, strict=strict_identities())
    validate_endpoint(agent_id, endpoint, strict=strict_identities())
    _validate_kid(agent_id, kid)
    if not store.has_namespace(developer.id, agent_id):
        raise StateConflictError("NAMESPACE_NOT_AUTHORIZED")
    current = store.resolve(agent_id)
    verification_record = current or AgentRecord(
        agent_id,
        endpoint,
        tuple(capabilities),
        kid,
        public_key,
        envelope.issued_at,
    )
    verify_envelope(
        envelope,
        record=verification_record,
        audience=load_registry_url(),
        nonce_state=None,
        expected_type="registry.publish",
        allowed_skew_seconds=allowed_skew(),
    )
    record = AgentRecord(agent_id, endpoint, tuple(capabilities), kid, public_key, envelope.issued_at)
    return store.publish(record, developer.id, envelope.id, _expiry(envelope))


def _rotate(store: RegistryStore, developer: Developer, envelope: SignedEnvelope) -> AgentRecord:
    payload = _payload(envelope, {"agent_id", "new_kid", "new_public_key", "proof"})
    agent_id = _text(payload, "agent_id")
    new_kid = _text(payload, "new_kid")
    new_public_key = _text(payload, "new_public_key")
    if envelope.sender != agent_id:
        raise AgentAuthError("SIGNER_MISMATCH", "Rotation sender does not match agent_id")
    if not store.has_namespace(developer.id, agent_id):
        raise StateConflictError("NAMESPACE_NOT_AUTHORIZED")
    current = store.resolve(agent_id)
    if current is None:
        raise StateConflictError("AGENT_NOT_FOUND")
    verify_envelope(
        envelope,
        record=current,
        audience=load_registry_url(),
        nonce_state=None,
        expected_type="registry.rotate",
        allowed_skew_seconds=allowed_skew(),
    )
    proof_raw = payload["proof"]
    if not isinstance(proof_raw, dict):
        raise AgentAuthError("ROTATION_PROOF_INVALID", "Rotation proof is missing")
    proof = SignedEnvelope.from_dict(proof_raw)
    proof_payload = _payload(proof, {"agent_id", "new_kid", "new_public_key"})
    expected_payload = {"agent_id": agent_id, "new_kid": new_kid, "new_public_key": new_public_key}
    if proof_payload != expected_payload or proof.reply_to != envelope.id:
        raise AgentAuthError("ROTATION_PROOF_INVALID", "Rotation proof does not match mutation")
    _validate_kid(agent_id, new_kid)
    new_record = AgentRecord(agent_id, current.endpoint, current.capabilities, new_kid, new_public_key, proof.issued_at)
    verify_envelope(
        proof,
        record=new_record,
        audience=load_registry_url(),
        nonce_state=None,
        expected_type="registry.rotate.proof",
        expected_reply_to=envelope.id,
        allowed_skew_seconds=allowed_skew(),
    )
    return store.rotate(
        agent_id=agent_id,
        developer_id=developer.id,
        current_kid=current.kid,
        new_kid=new_kid,
        new_public_key=new_public_key,
        request_ids=(envelope.id, proof.id),
        expires_at=_expiry(envelope),
    )


def _revoke(store: RegistryStore, developer: Developer, envelope: SignedEnvelope) -> None:
    payload = _payload(envelope, {"agent_id"})
    agent_id = _text(payload, "agent_id")
    if envelope.sender != agent_id:
        raise AgentAuthError("SIGNER_MISMATCH", "Revoke sender does not match agent_id")
    if not store.has_namespace(developer.id, agent_id):
        raise StateConflictError("NAMESPACE_NOT_AUTHORIZED")
    current = store.resolve(agent_id)
    if current is None:
        raise StateConflictError("AGENT_NOT_FOUND")
    verify_envelope(
        envelope,
        record=current,
        audience=load_registry_url(),
        nonce_state=None,
        expected_type="registry.revoke",
        allowed_skew_seconds=allowed_skew(),
    )
    store.revoke(
        agent_id=agent_id,
        developer_id=developer.id,
        current_kid=current.kid,
        request_id=envelope.id,
        expires_at=_expiry(envelope),
    )


def _authenticate(store: RegistryStore, authorization: str | None, client_id: str | None) -> Developer:
    if not authorization or not authorization.startswith("Bearer ") or not client_id:
        raise AgentAuthError("DEVELOPER_AUTH_MISSING", "Developer credentials are required")
    developer = store.get_developer(client_id)
    if developer is None or developer.status != "active":
        raise AgentAuthError("DEVELOPER_NOT_FOUND", "Developer is not active")
    if not verify_api_key(authorization.removeprefix("Bearer ").strip(), developer.api_key_hash):
        raise AgentAuthError("DEVELOPER_KEY_INVALID", "Developer API key is invalid")
    return developer


def _payload(envelope: SignedEnvelope, fields: set[str]) -> dict[str, Any]:
    import json

    from agent_auth._protocol import b64url_decode

    try:
        value = json.loads(b64url_decode(envelope.payload))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentAuthError("PAYLOAD_INVALID", "Mutation payload is invalid") from exc
    if not isinstance(value, dict) or set(value) != fields:
        raise AgentAuthError("PAYLOAD_INVALID", "Mutation payload fields are invalid")
    return value


def _text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise AgentAuthError("PAYLOAD_INVALID", f"{key} must be a non-empty string")
    return value


def _validate_kid(agent_id: str, kid: str) -> None:
    prefix = f"{agent_id}#key:v"
    if not kid.startswith(prefix) or not kid.removeprefix(prefix).isdigit() or int(kid.removeprefix(prefix)) <= 0:
        raise AgentAuthError("KID_INVALID", "kid must bind the Agent ID to a positive Vault key version")


def _expiry(envelope: SignedEnvelope) -> str:
    value = parse_timestamp(envelope.issued_at) + timedelta(seconds=allowed_skew())
    return value.isoformat().replace("+00:00", "Z")


def _etag(value: object) -> str:
    import json

    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return f'"{digest}"'
