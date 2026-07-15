from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from agent_auth_registry.admin import build_parser
from agent_auth_registry.admin import main as admin_main
from agent_auth_registry.app import create_app, load_registry_url
from agent_auth_registry.run import build_parser as build_server_parser
from agent_auth_registry.security import hash_api_key, verify_api_key
from agent_auth_registry.storage import RegistryStore, StateConflictError, UnsupportedSchemaVersionError
from fastapi.testclient import TestClient

from agent_auth._protocol import DevSigner, sign_envelope
from agent_auth._types import AgentRecord


def _signer(agent_id: str, version: int) -> DevSigner:
    signer = DevSigner(agent_id)
    signer._kid = f"{agent_id}#key:v{version}"
    return signer


def _envelope(signer: DevSigner, call_type: str, payload: object, **kwargs: object):
    return asyncio.run(
        sign_envelope(
            sender=signer.kid.split("#", 1)[0],
            audience="http://testserver",
            call_type=call_type,
            payload=payload,
            signer=signer,
            **kwargs,
        )
    )


@pytest.fixture
def registry(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AGENT_REGISTRY_STRICT_IDENTITIES", "0")
    monkeypatch.setenv("AGENT_REGISTRY_URL", "http://testserver")
    store = RegistryStore(tmp_path / "registry.sqlite3")
    api_key = "developer-secret"
    developer = store.create_developer("team", hash_api_key(api_key))
    store.grant_namespace(developer.id, "127.0.0.1", "/demo")
    with TestClient(create_app(store=store)) as client:
        yield store, client, {"Authorization": f"Bearer {api_key}", "X-Registry-Client-ID": "team"}


def test_registry_has_exactly_five_routes(registry) -> None:
    _, client, _ = registry
    routes = {
        (next(iter(route.methods)), route.path)
        for route in client.app.routes
        if getattr(route, "methods", None) and not route.path.startswith(("/openapi", "/docs", "/redoc"))
    }
    assert routes == {
        ("GET", "/health/live"),
        ("GET", "/health/ready"),
        ("GET", "/v1/agents/resolve"),
        ("GET", "/.well-known/agent.json"),
        ("POST", "/v1/agents"),
    }
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    assert client.get("/v1/agents/resolve", params={"agent_id": "bad"}).status_code == 400
    first = client.get("/.well-known/agent.json")
    assert client.get("/.well-known/agent.json", headers={"If-None-Match": first.headers["etag"]}).status_code == 304
    server_args = build_server_parser().parse_args(["--host", "127.0.0.1", "--port", "9000"])
    assert (server_args.host, server_args.port) == ("127.0.0.1", 9000)


def test_registry_public_url_is_required_and_https(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_REGISTRY_STRICT_IDENTITIES", "1")
    monkeypatch.delenv("AGENT_REGISTRY_URL", raising=False)
    with pytest.raises(RuntimeError, match="required"):
        load_registry_url()
    monkeypatch.setenv("AGENT_REGISTRY_URL", "http://registry.example.com")
    with pytest.raises(RuntimeError, match="HTTPS"):
        load_registry_url()


def test_resolve_etag_returns_not_modified(registry) -> None:
    _, client, headers = registry
    agent_id = "agent://127.0.0.1/demo/cache"
    signer = _signer(agent_id, 1)
    publish = _envelope(
        signer,
        "registry.publish",
        {
            "agent_id": agent_id,
            "endpoint": "http://127.0.0.1:9002/invoke",
            "capabilities": [],
            "kid": signer.kid,
            "public_key": signer.public_key,
        },
    )
    assert client.post("/v1/agents", json=publish.as_dict(), headers=headers).status_code == 200
    resolved = client.get("/v1/agents/resolve", params={"agent_id": agent_id})
    cached = client.get(
        "/v1/agents/resolve",
        params={"agent_id": agent_id},
        headers={"If-None-Match": resolved.headers["etag"]},
    )
    assert cached.status_code == 304


def test_publish_update_rotate_revoke_lifecycle(registry) -> None:
    store, client, headers = registry
    agent_id = "agent://127.0.0.1/demo/researcher"
    first = _signer(agent_id, 1)
    metadata = {
        "agent_id": agent_id,
        "endpoint": "http://127.0.0.1:9001/invoke",
        "capabilities": ["research"],
        "kid": first.kid,
        "public_key": first.public_key,
    }
    publish = _envelope(first, "registry.publish", metadata)
    response = client.post("/v1/agents", json=publish.as_dict(), headers=headers)
    assert response.status_code == 200
    assert response.json()["kid"] == first.kid

    metadata["capabilities"] = ["research", "summarize"]
    update = _envelope(first, "registry.publish", metadata)
    assert client.post("/v1/agents", json=update.as_dict(), headers=headers).status_code == 200
    assert client.get("/v1/agents/resolve", params={"agent_id": agent_id}).json()["capabilities"] == [
        "research",
        "summarize",
    ]

    second = _signer(agent_id, 2)
    request_id = "rotation-request"
    proof_payload = {"agent_id": agent_id, "new_kid": second.kid, "new_public_key": second.public_key}
    proof = _envelope(second, "registry.rotate.proof", proof_payload, reply_to=request_id)
    rotation = _envelope(first, "registry.rotate", {**proof_payload, "proof": proof.as_dict()}, request_id=request_id)
    rotated = client.post("/v1/agents", json=rotation.as_dict(), headers=headers)
    assert rotated.status_code == 200
    assert rotated.json()["kid"] == second.kid

    replay = client.post("/v1/agents", json=rotation.as_dict(), headers=headers)
    assert replay.status_code == 409
    assert replay.json()["detail"] == "NONCE_REPLAYED"

    revoke = _envelope(second, "registry.revoke", {"agent_id": agent_id})
    assert client.post("/v1/agents", json=revoke.as_dict(), headers=headers).status_code == 200
    assert client.get("/v1/agents/resolve", params={"agent_id": agent_id}).status_code == 404
    assert client.get("/.well-known/agent.json").json() == {"version": 1, "agents": []}
    assert store.owner(agent_id) is not None


def test_publish_rejects_identity_namespace_owner_and_signature(registry) -> None:
    store, client, headers = registry
    agent_id = "agent://127.0.0.1/other/a"
    signer = _signer(agent_id, 1)
    metadata = {
        "agent_id": agent_id,
        "endpoint": "http://127.0.0.1/a",
        "capabilities": [],
        "kid": signer.kid,
        "public_key": signer.public_key,
    }
    envelope = _envelope(signer, "registry.publish", metadata)
    assert client.post("/v1/agents", json=envelope.as_dict(), headers=headers).status_code == 403
    assert client.post("/v1/agents", json=envelope.as_dict()).status_code == 401
    wrong_key = {"Authorization": "Bearer wrong", "X-Registry-Client-ID": "team"}
    assert client.post("/v1/agents", json=envelope.as_dict(), headers=wrong_key).status_code == 401

    allowed_id = "agent://127.0.0.1/demo/a"
    allowed = _signer(allowed_id, 1)
    metadata.update(
        agent_id=allowed_id,
        endpoint="http://127.0.0.1/a",
        kid=allowed.kid,
        public_key=allowed.public_key,
    )
    good = _envelope(allowed, "registry.publish", metadata)
    tampered = good.as_dict()
    tampered["signature"] = "bad"
    assert client.post("/v1/agents", json=tampered, headers=headers).status_code == 401

    other = store.create_developer("other", hash_api_key("other-secret"))
    assert other.id
    other_headers = {"Authorization": "Bearer other-secret", "X-Registry-Client-ID": "other"}
    assert client.post("/v1/agents", json=good.as_dict(), headers=other_headers).status_code == 403


def test_registry_rejects_bad_mutation_shapes(registry) -> None:
    _, client, headers = registry
    agent_id = "agent://127.0.0.1/demo/shapes"
    signer = _signer(agent_id, 1)
    unsupported = _envelope(signer, "registry.unknown", {})
    assert client.post("/v1/agents", json=unsupported.as_dict(), headers=headers).status_code == 400
    assert client.post("/v1/agents", json=[1], headers=headers).status_code == 400

    base = {
        "agent_id": agent_id,
        "endpoint": "http://127.0.0.1/shapes",
        "capabilities": [1],
        "kid": signer.kid,
        "public_key": signer.public_key,
    }
    invalid_capability = _envelope(signer, "registry.publish", base)
    assert client.post("/v1/agents", json=invalid_capability.as_dict(), headers=headers).status_code == 400
    base["capabilities"] = []
    base["kid"] = f"{agent_id}#bad"
    bad_kid = _envelope(signer, "registry.publish", base)
    assert client.post("/v1/agents", json=bad_kid.as_dict(), headers=headers).status_code == 401


def test_registry_rotate_and_revoke_rejection_matrix(registry) -> None:
    _, client, headers = registry
    agent_id = "agent://127.0.0.1/demo/mutation-errors"
    first = _signer(agent_id, 1)
    second = _signer(agent_id, 2)
    proof_payload = {"agent_id": agent_id, "new_kid": second.kid, "new_public_key": second.public_key}

    missing_rotate = _envelope(first, "registry.rotate", {**proof_payload, "proof": {}})
    assert client.post("/v1/agents", json=missing_rotate.as_dict(), headers=headers).status_code == 409
    missing_revoke = _envelope(first, "registry.revoke", {"agent_id": agent_id})
    assert client.post("/v1/agents", json=missing_revoke.as_dict(), headers=headers).status_code == 409

    publish = _envelope(
        first,
        "registry.publish",
        {
            "agent_id": agent_id,
            "endpoint": "http://127.0.0.1/mutation-errors",
            "capabilities": [],
            "kid": first.kid,
            "public_key": first.public_key,
        },
    )
    assert client.post("/v1/agents", json=publish.as_dict(), headers=headers).status_code == 200
    no_proof = _envelope(first, "registry.rotate", {**proof_payload, "proof": None})
    assert client.post("/v1/agents", json=no_proof.as_dict(), headers=headers).status_code == 400

    request_id = "mismatched-proof-request"
    proof = _envelope(second, "registry.rotate.proof", {**proof_payload, "new_kid": first.kid}, reply_to=request_id)
    mismatch = _envelope(
        first,
        "registry.rotate",
        {**proof_payload, "proof": proof.as_dict()},
        request_id=request_id,
    )
    assert client.post("/v1/agents", json=mismatch.as_dict(), headers=headers).status_code == 400

    wrong_subject = _envelope(first, "registry.revoke", {"agent_id": "agent://127.0.0.1/demo/other"})
    assert client.post("/v1/agents", json=wrong_subject.as_dict(), headers=headers).status_code == 401


def test_namespace_overlap_and_api_key_security(tmp_path) -> None:
    store = RegistryStore(tmp_path / "registry.sqlite3")
    key_hash = hash_api_key("secret")
    assert verify_api_key("secret", key_hash)
    assert not verify_api_key("wrong", key_hash)
    first = store.create_developer("one", key_hash)
    second = store.create_developer("two", hash_api_key("two"))
    store.grant_namespace(first.id, "agents.example.com", "/team")
    with pytest.raises(StateConflictError, match="NAMESPACE_OVERLAP"):
        store.grant_namespace(second.id, "agents.example.com", "/team/child")
    with pytest.raises(StateConflictError, match="CLIENT_ID_EXISTS"):
        store.create_developer("one", key_hash)


def test_registry_admin_groups_and_database_commands(tmp_path, capsys) -> None:
    parser = build_parser()
    group = next(action for action in parser._actions if action.dest == "group")
    assert set(group.choices) == {"developer", "namespace", "agent", "db"}
    db = tmp_path / "registry.sqlite3"
    assert admin_main(["--db-path", str(db), "developer", "add", "--client-id", "team"]) == 0
    output = capsys.readouterr().out
    assert '"api_key"' in output
    assert admin_main(["--db-path", str(db), "db", "check"]) == 0
    backup = tmp_path / "backup.sqlite3"
    assert admin_main(["--db-path", str(db), "db", "backup", "--output", str(backup)]) == 0
    assert backup.exists()


def test_storage_admin_lifecycle_and_conflicts(tmp_path) -> None:
    store = RegistryStore(tmp_path / "registry.sqlite3")
    developer = store.create_developer("team", hash_api_key("one"))
    namespace = store.grant_namespace(developer.id, "agents.example.com", "/team")
    assert store.list_developers() == [developer]
    assert store.list_namespaces("team") == [namespace]
    store.rotate_developer_key("team", hash_api_key("two"))
    assert verify_api_key("two", store.get_developer("team").api_key_hash)  # type: ignore[union-attr]
    store.revoke_namespace(namespace.id)
    with pytest.raises(StateConflictError, match="NAMESPACE_NOT_FOUND"):
        store.revoke_namespace(namespace.id)
    store.revoke_developer("team")
    with pytest.raises(StateConflictError, match="DEVELOPER_NOT_FOUND"):
        store.revoke_developer("team")
    with pytest.raises(StateConflictError, match="DEVELOPER_NOT_FOUND"):
        store.rotate_developer_key("missing", hash_api_key("x"))


def test_storage_rejects_unknown_schema(tmp_path) -> None:
    path = tmp_path / "future.sqlite3"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        connection.execute("INSERT INTO schema_version VALUES (99, 'future')")
    with pytest.raises(UnsupportedSchemaVersionError):
        RegistryStore(path)


def test_storage_mutation_conflict_matrix(tmp_path) -> None:
    store = RegistryStore(tmp_path / "registry.sqlite3")
    owner = store.create_developer("owner", hash_api_key("owner"))
    other = store.create_developer("other", hash_api_key("other"))
    agent_id = "agent://agents.example.com/team/a"
    record = AgentRecord(agent_id, "https://agents.example.com/invoke", (), f"{agent_id}#key:v1", "public-1", "now")
    expiry = "2999-01-01T00:00:00Z"
    store.publish(record, owner.id, "publish-1", expiry)

    with pytest.raises(StateConflictError, match="OWNER_MISMATCH"):
        store.publish(record, other.id, "publish-owner", expiry)
    changed = AgentRecord(agent_id, record.endpoint, (), f"{agent_id}#key:v2", "public-2", "now")
    with pytest.raises(StateConflictError, match="PUBLISH_CANNOT_CHANGE_KEY"):
        store.publish(changed, owner.id, "publish-key", expiry)
    with pytest.raises(StateConflictError, match="AGENT_NOT_FOUND"):
        store.rotate(
            agent_id="agent://agents.example.com/team/missing",
            developer_id=owner.id,
            current_kid="missing",
            new_kid="new",
            new_public_key="new",
            request_ids=("m1", "m2"),
            expires_at=expiry,
        )
    with pytest.raises(StateConflictError, match="OWNER_MISMATCH"):
        store.rotate(
            agent_id=agent_id,
            developer_id=other.id,
            current_kid=record.kid,
            new_kid=f"{agent_id}#key:v2",
            new_public_key="public-2",
            request_ids=("o1", "o2"),
            expires_at=expiry,
        )
    with pytest.raises(StateConflictError, match="CURRENT_KEY_MISMATCH"):
        store.rotate(
            agent_id=agent_id,
            developer_id=owner.id,
            current_kid="wrong",
            new_kid=f"{agent_id}#key:v2",
            new_public_key="public-2",
            request_ids=("c1", "c2"),
            expires_at=expiry,
        )
    with pytest.raises(StateConflictError, match="KID_ALREADY_USED"):
        store.rotate(
            agent_id=agent_id,
            developer_id=owner.id,
            current_kid=record.kid,
            new_kid=record.kid,
            new_public_key="public-2",
            request_ids=("k1", "k2"),
            expires_at=expiry,
        )
    with pytest.raises(StateConflictError, match="AGENT_NOT_FOUND"):
        store.revoke(
            agent_id="agent://agents.example.com/team/missing",
            developer_id=owner.id,
            current_kid="missing",
            request_id="r-missing",
            expires_at=expiry,
        )
    with pytest.raises(StateConflictError, match="OWNER_MISMATCH"):
        store.revoke(
            agent_id=agent_id,
            developer_id=other.id,
            current_kid=record.kid,
            request_id="r-owner",
            expires_at=expiry,
        )
    with pytest.raises(StateConflictError, match="CURRENT_KEY_MISMATCH"):
        store.revoke(
            agent_id=agent_id,
            developer_id=owner.id,
            current_kid="wrong",
            request_id="r-key",
            expires_at=expiry,
        )
    store.admin_revoke_agent(agent_id)
    with pytest.raises(StateConflictError, match="AGENT_REVOKED"):
        store.publish(record, owner.id, "publish-revoked", expiry)
    with pytest.raises(StateConflictError, match="AGENT_NOT_FOUND"):
        store.admin_revoke_agent(agent_id)
