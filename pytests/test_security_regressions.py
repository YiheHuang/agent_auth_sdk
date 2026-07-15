from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from agent_auth_registry.admin import app as registry_admin_app
from agent_auth_registry.app import create_app as create_registry_app
from agent_auth_registry.storage import (
    AgentStateConflictError,
    RegistryStore,
    UnsupportedSchemaVersionError,
)
from typer.testing import CliRunner

from agent_auth_sdk import (
    AgentAuthASGIMiddleware,
    AgentVerifier,
    InMemoryNonceStore,
    MetadataResolverConfig,
    RemoteAgentClient,
    VerificationConfig,
    verify_agent_message,
)
from agent_auth_sdk.agent import AgentInstance
from agent_auth_sdk.config import STRICT_PROFILE, TEST_PROFILE, DiscoveryMode
from agent_auth_sdk.crypto import public_key_to_base64url
from agent_auth_sdk.errors import MetadataValidationError
from agent_auth_sdk.http_utils import canonical_json_bytes
from agent_auth_sdk.identity import parse_agent_id
from agent_auth_sdk.metadata import _validate_direct_target, resolve_agent
from agent_auth_sdk.models import AgentKey, AgentRegistryDocument, AgentRegistryEntry
from agent_auth_sdk.registry_security import hash_api_key, sign_registry_publish_request
from agent_auth_sdk.signing import sign_http_request
from agent_auth_sdk.verification import verify_http_request
from pytests.test_sdk_integration import _generate_es256_pem_pair, _TestEs256Signer


def _seed(store: RegistryStore, *, developer_id: str, client_id: str, api_key: str, domain: str) -> None:
    store.create_developer(
        developer_id=developer_id,
        client_id=client_id,
        api_key_hash=hash_api_key(api_key),
    )
    store.create_namespace(developer_id=developer_id, domain=domain, path_prefix="/")


@pytest.mark.anyio
async def test_direct_discovery_pins_validated_ip_and_rejects_ssrf(monkeypatch) -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="public.example",
        name="sender",
        organization="Test",
        endpoint="https://public.example/invoke",
        signer=_TestEs256Signer(private_pem, kid="key-1"),
        public_key_pem=public_pem,
        kid="key-1",
    )
    seen_request: httpx.Request | None = None

    def public_dns(*args, **kwargs):
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_request
        seen_request = request
        return httpx.Response(200, json=agent.metadata.model_dump(mode="json"))

    monkeypatch.setattr("agent_auth_sdk.metadata.socket.getaddrinfo", public_dns)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await resolve_agent(
            agent.agent_id,
            profile=STRICT_PROFILE,
            http_client=client,
            config=MetadataResolverConfig(
                profile=STRICT_PROFILE,
                discovery_mode=DiscoveryMode.DIRECT_ONLY,
            ),
        )
    assert result.source_url == "https://public.example/.well-known/agent.json"
    assert seen_request is not None
    assert seen_request.url.host == "93.184.216.34"
    assert seen_request.headers["host"] == "public.example"
    assert seen_request.extensions["sni_hostname"] == "public.example"

    for address in ("127.0.0.1", "::1", "10.0.0.1", "fd00::1"):

        def private_dns(*args, _address: str = address, **kwargs):
            return [(2, 1, 6, "", (_address, 443))]

        monkeypatch.setattr("agent_auth_sdk.metadata.socket.getaddrinfo", private_dns)
        with pytest.raises(MetadataValidationError, match="non-global"):
            await _validate_direct_target("https://private.example/.well-known/agent.json", STRICT_PROFILE)

    with pytest.raises(MetadataValidationError, match="userinfo"):
        await _validate_direct_target("https://user@public.example/.well-known/agent.json", STRICT_PROFILE)

    monkeypatch.setattr("agent_auth_sdk.metadata.socket.getaddrinfo", public_dns)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"location": "https://other.example"})
        )
    ) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await resolve_agent(
                agent.agent_id,
                profile=STRICT_PROFILE,
                http_client=client,
                config=MetadataResolverConfig(
                    profile=STRICT_PROFILE,
                    discovery_mode=DiscoveryMode.DIRECT_ONLY,
                ),
            )


@pytest.mark.anyio
async def test_first_publish_cannot_overwrite_existing_owner(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "registry.sqlite3"
    monkeypatch.setenv("AGENT_REGISTRY_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENT_REGISTRY_PATH", str(tmp_path / "agent.json"))
    store = RegistryStore(db_path)
    _seed(store, developer_id="legit", client_id="legit-client", api_key="legit-key", domain="victim.example")
    _seed(store, developer_id="attacker", client_id="attacker-client", api_key="attacker-key", domain="decoy.example")

    legit_private, legit_public = _generate_es256_pem_pair()
    victim = AgentInstance.from_signer(
        domain="victim.example",
        name="worker",
        organization="Victim",
        endpoint="https://victim.example/invoke",
        signer=_TestEs256Signer(legit_private, kid="vault:legit"),
        public_key_pem=legit_public,
        kid="vault:legit",
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        await victim.publish(
            registry_url="http://registry.local/registry/agents/publish",
            client_id="legit-client",
            api_key="legit-key",
            http_client=client,
        )

        attacker_private, attacker_public = _generate_es256_pem_pair()
        attacker_signer = _TestEs256Signer(attacker_private, kid="vault:attacker")
        attacker_key = AgentKey(
            kid="vault:attacker",
            public_key_pem=attacker_public,
            public_key_base64url=public_key_to_base64url(attacker_public),
        )
        metadata = victim.metadata.model_copy(update={"organization": "Attacker", "keys": [attacker_key]})
        payload = {
            "agent_id": "agent://decoy.example/unused",
            "metadata": metadata.model_dump(mode="json"),
            "publish_intent": "upsert_metadata",
        }
        signed = await sign_registry_publish_request(
            path="/registry/agents/publish",
            host="registry.local",
            body=payload,
            agent_id=payload["agent_id"],
            client_id="attacker-client",
            signer=attacker_signer,
        )
        response = await client.post(
            "/registry/agents/publish",
            content=canonical_json_bytes(payload),
            headers={
                **signed.headers,
                "authorization": "Bearer attacker-key",
                "content-type": "application/json",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "METADATA_AGENT_ID_MISMATCH"
    assert RegistryStore(db_path).get_ownership(victim.agent_id).owner_developer_id == "legit"


@pytest.mark.anyio
async def test_registry_signature_covers_actual_raw_body_bytes(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "registry.sqlite3"
    monkeypatch.setenv("AGENT_REGISTRY_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENT_REGISTRY_PATH", str(tmp_path / "agent.json"))
    store = RegistryStore(db_path)
    _seed(store, developer_id="dev", client_id="developer", api_key="secret", domain="example.com")
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="example.com",
        name="worker",
        organization="Test",
        endpoint="https://example.com/invoke",
        signer=_TestEs256Signer(private_pem, kid="key-1"),
        public_key_pem=public_pem,
        kid="key-1",
    )
    payload = {
        "agent_id": agent.agent_id,
        "metadata": agent.metadata.model_dump(mode="json"),
        "publish_intent": "upsert_metadata",
    }
    signed = await sign_registry_publish_request(
        path="/v1/agents/publish",
        host="registry.local",
        body=canonical_json_bytes(payload),
        agent_id=agent.agent_id,
        client_id="developer",
        signer=agent.signer,
    )
    transport = httpx.ASGITransport(app=create_registry_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://registry.local") as client:
        response = await client.post(
            "/v1/agents/publish",
            json=payload,
            headers={**signed.headers, "authorization": "Bearer secret"},
        )
    assert response.status_code == 401
    assert response.json()["detail"] == "SIGNATURE_INVALID"
    assert store.get_ownership(agent.agent_id) is None


@pytest.mark.anyio
async def test_concurrent_same_nonce_only_one_verification_succeeds() -> None:
    private_pem, public_pem = _generate_es256_pem_pair()
    signer = _TestEs256Signer(private_pem, kid="vault:test")
    agent = AgentInstance.from_signer(
        domain="127.0.0.1:9001",
        name="publisher",
        organization="Audit",
        endpoint="http://127.0.0.1:9001/invoke",
        signer=signer,
        public_key_pem=public_pem,
        kid="vault:test",
    )
    signed = await sign_http_request(
        method="POST",
        url="http://127.0.0.1:8010/invoke",
        body={"x": 1},
        agent_id=agent.agent_id,
        signer=signer,
        nonce="shared-nonce",
    )

    async def handler(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.03)
        return httpx.Response(200, json=agent.metadata.model_dump(mode="json"))

    nonce_store = InMemoryNonceStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:

        async def verify_once():
            return await verify_http_request(
                method="POST",
                url="http://127.0.0.1:8010/invoke",
                headers=signed.headers,
                body={"x": 1},
                nonce_store=nonce_store,
                http_client=client,
                config=VerificationConfig(profile=TEST_PROFILE),
            )

        results = await asyncio.gather(verify_once(), verify_once())

    assert sorted(result.ok for result in results) == [False, True]
    assert {result.code for result in results if not result.ok} == {"NONCE_REPLAYED"}


@pytest.mark.anyio
async def test_untrusted_validation_errors_return_failure() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(500))) as client:
        malformed = await verify_agent_message(
            message={"bad": "shape"},
            nonce_store=InMemoryNonceStore(),
            http_client=client,
        )
        headers = {
            "x-agent-id": "agent://example.com/sender",
            "x-agent-kid": "kid",
            "x-agent-timestamp": datetime.now().replace(microsecond=0).isoformat(),
            "x-agent-nonce": "nonce",
            "x-agent-signature": "invalid",
            "x-agent-signature-input": (
                "method path body-digest x-agent-id x-agent-kid x-agent-timestamp x-agent-nonce host"
            ),
            "host": "receiver.example",
        }
        naive_time = await verify_http_request(
            method="POST",
            url="https://receiver.example/invoke",
            headers=headers,
            body=b"",
            nonce_store=InMemoryNonceStore(),
            http_client=client,
            now=datetime.now(UTC),
        )

    assert malformed.ok is False and malformed.code == "MESSAGE_INVALID"
    assert naive_time.ok is False and naive_time.code == "TIMESTAMP_EXPIRED"


def test_agent_id_rejects_userinfo_query_and_non_normalized_host() -> None:
    for value in (
        "agent://user@example.com/worker",
        "agent://example.com/worker?debug=1",
        "agent://EXAMPLE.com/worker",
        "agent://example.com/a%2Fb",
        "agent://example%2ecom/worker",
        "agent://example.com:0/worker",
    ):
        with pytest.raises(ValueError):
            parse_agent_id(value)


def test_namespace_overlap_is_rejected(tmp_path) -> None:
    store = RegistryStore(tmp_path / "registry.sqlite3")
    store.create_developer(developer_id="dev-a", client_id="a", api_key_hash=hash_api_key("a"))
    store.create_developer(developer_id="dev-b", client_id="b", api_key_hash=hash_api_key("b"))
    store.create_namespace(developer_id="dev-a", domain="example.com", path_prefix="/team")
    with pytest.raises(ValueError, match="overlaps"):
        store.create_namespace(developer_id="dev-b", domain="example.com", path_prefix="/team/worker")


@pytest.mark.anyio
async def test_concurrent_overlapping_namespace_grants_only_one(tmp_path) -> None:
    store = RegistryStore(tmp_path / "registry.sqlite3")
    for developer_id in ("dev-a", "dev-b"):
        store.create_developer(
            developer_id=developer_id,
            client_id=developer_id,
            api_key_hash=hash_api_key("secret"),
        )
    barrier = threading.Barrier(2)

    def grant(developer_id: str) -> bool:
        barrier.wait()
        try:
            store.create_namespace(
                developer_id=developer_id,
                domain="example.com",
                path_prefix="/team",
            )
        except ValueError:
            return False
        return True

    results = await asyncio.gather(
        asyncio.to_thread(grant, "dev-a"),
        asyncio.to_thread(grant, "dev-b"),
    )
    assert sum(results) == 1


def test_stale_registry_update_rolls_back_state_and_nonce(tmp_path) -> None:
    store = RegistryStore(tmp_path / "registry.sqlite3")
    store.create_developer(developer_id="dev", client_id="dev", api_key_hash=hash_api_key("secret"))
    private_pem, public_pem = _generate_es256_pem_pair()
    agent = AgentInstance.from_signer(
        domain="example.com",
        name="worker",
        organization="Test",
        endpoint="https://example.com/invoke",
        signer=_TestEs256Signer(private_pem, kid="key-1"),
        public_key_pem=public_pem,
        kid="key-1",
    )
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    assert store.commit_agent_operation(
        metadata=agent.metadata,
        developer_id="dev",
        current_kid="key-1",
        public_key_fingerprint="fingerprint",
        nonce_keys=["create"],
        nonce_expires_at=expires_at,
        action="publish",
        source_ip=None,
        create=True,
    )
    stale = store.get_ownership(agent.agent_id)
    assert stale is not None
    first_update = agent.metadata.model_copy(update={"organization": "First"})
    assert store.commit_agent_operation(
        metadata=first_update,
        developer_id="dev",
        current_kid="key-1",
        public_key_fingerprint="fingerprint",
        nonce_keys=["first-update"],
        nonce_expires_at=expires_at,
        action="publish",
        source_ip=None,
        create=False,
        created_at=stale.created_at,
        expected_updated_at=stale.updated_at,
    )
    with pytest.raises(AgentStateConflictError):
        store.commit_agent_operation(
            metadata=agent.metadata.model_copy(update={"organization": "Stale"}),
            developer_id="dev",
            current_kid="key-1",
            public_key_fingerprint="fingerprint",
            nonce_keys=["stale-update"],
            nonce_expires_at=expires_at,
            action="publish",
            source_ip=None,
            create=False,
            created_at=stale.created_at,
            expected_updated_at=stale.updated_at,
        )
    assert not store.has_nonce("stale-update")
    entry = store.get_registry_entry(agent.agent_id)
    assert entry is not None
    assert entry.owner_developer_id == "dev"


@pytest.mark.anyio
async def test_remote_http_boundary_verifies_request_and_signed_response() -> None:
    source_private, source_public = _generate_es256_pem_pair()
    target_private, target_public = _generate_es256_pem_pair()
    source = AgentInstance.from_signer(
        domain="source.local",
        name="caller",
        organization="Test",
        endpoint="https://source.local/invoke",
        signer=_TestEs256Signer(source_private, kid="source-key"),
        public_key_pem=source_public,
        kid="source-key",
    )
    target = AgentInstance.from_signer(
        domain="target.local",
        name="worker",
        organization="Test",
        endpoint="https://target.local/invoke",
        signer=_TestEs256Signer(target_private, kid="target-key"),
        public_key_pem=target_public,
        kid="target-key",
    )
    document = AgentRegistryDocument(
        updated_at=datetime.now(UTC),
        agents=[
            AgentRegistryEntry(agent_id=source.agent_id, metadata=source.metadata, published_at=datetime.now(UTC)),
            AgentRegistryEntry(agent_id=target.agent_id, metadata=target.metadata, published_at=datetime.now(UTC)),
        ],
    )

    async def registry_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=document.model_dump(mode="json"))

    receiver_metadata_client = httpx.AsyncClient(transport=httpx.MockTransport(registry_handler))
    receiver_verifier = AgentVerifier(
        verification_config=VerificationConfig(profile=TEST_PROFILE),
        resolver_config=MetadataResolverConfig(
            profile=TEST_PROFILE,
            registry_url="http://registry.local/.well-known/agent.json",
        ),
        http_client=receiver_metadata_client,
    )

    async def endpoint(scope, receive, send):
        assert scope["state"]["agent_auth"].agent_id == source.agent_id
        event = await receive()
        payload = json.loads(event["body"])
        signed_result = await target.sign_message(
            payload={"echo": payload},
            recipient=source.agent_id,
            message_type="agent.call.result",
        )
        body = signed_result.model_dump_json().encode("utf-8")
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    target_app = AgentAuthASGIMiddleware(endpoint, verifier=receiver_verifier)
    target_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=target_app), base_url="http://target.local")
    source_metadata_client = httpx.AsyncClient(transport=httpx.MockTransport(registry_handler))
    source_verifier = AgentVerifier(
        verification_config=VerificationConfig(profile=TEST_PROFILE),
        resolver_config=MetadataResolverConfig(
            profile=TEST_PROFILE,
            registry_url="http://registry.local/.well-known/agent.json",
        ),
        http_client=source_metadata_client,
    )
    remote = RemoteAgentClient(sender=source, verifier=source_verifier, http_client=target_client)
    try:
        result = await remote.call(
            target_url="http://target.local/invoke",
            target_agent_id=target.agent_id,
            payload={"task": "ping"},
        )
    finally:
        await target_client.aclose()
        await source_metadata_client.aclose()
        await receiver_metadata_client.aclose()

    assert result == {"echo": {"task": "ping"}}


def test_registry_schema_check_backup_and_future_version_rejection(tmp_path) -> None:
    db_path = tmp_path / "registry.sqlite3"
    store = RegistryStore(db_path)
    assert store.schema_status() == {
        "ok": True,
        "schema_version": 1,
        "expected_schema_version": 1,
        "integrity": "ok",
    }
    backup_path = tmp_path / "backup" / "registry.sqlite3"
    assert store.backup(backup_path) == backup_path
    assert RegistryStore(backup_path).schema_status()["ok"] is True

    runner = CliRunner()
    checked = runner.invoke(registry_admin_app, ["db", "check", "--db-path", str(db_path)])
    assert checked.exit_code == 0
    assert '"schema_version": 1' in checked.stdout

    future_path = tmp_path / "future.sqlite3"
    conn = sqlite3.connect(future_path)
    try:
        conn.execute("CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        conn.execute("INSERT INTO schema_version(version, applied_at) VALUES (99, CURRENT_TIMESTAMP)")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(UnsupportedSchemaVersionError, match="version 99"):
        RegistryStore(future_path)


def test_registry_admin_core_commands(tmp_path) -> None:
    db_path = tmp_path / "admin.sqlite3"
    runner = CliRunner()
    created = runner.invoke(
        registry_admin_app,
        ["create-developer", "--client-id", "team-a", "--db-path", str(db_path)],
    )
    assert created.exit_code == 0, created.output
    developer = json.loads(created.stdout)
    assert developer["client_id"] == "team-a"
    assert developer["api_key"]

    granted = runner.invoke(
        registry_admin_app,
        [
            "grant-namespace",
            "--client-id",
            "team-a",
            "--domain",
            "agents.example.com",
            "--path-prefix",
            "/team-a",
            "--db-path",
            str(db_path),
        ],
    )
    assert granted.exit_code == 0, granted.output
    namespace = json.loads(granted.stdout)

    listed = runner.invoke(
        registry_admin_app,
        ["list-namespaces", "--client-id", "team-a", "--db-path", str(db_path)],
    )
    assert listed.exit_code == 0
    assert json.loads(listed.stdout)[0]["path_prefix"] == "/team-a"

    rotated = runner.invoke(
        registry_admin_app,
        ["rotate-api-key", "--client-id", "team-a", "--db-path", str(db_path)],
    )
    assert rotated.exit_code == 0
    assert json.loads(rotated.stdout)["api_key"] != developer["api_key"]

    inspected = runner.invoke(
        registry_admin_app,
        ["inspect-agent", "--agent-id", "agent://agents.example.com/team-a/missing", "--db-path", str(db_path)],
    )
    assert inspected.exit_code == 0
    assert json.loads(inspected.stdout) == {"ownership": None, "entry": None}

    revoked_namespace = runner.invoke(
        registry_admin_app,
        ["revoke-namespace", "--namespace-id", namespace["namespace_id"], "--db-path", str(db_path)],
    )
    assert revoked_namespace.exit_code == 0
    revoked_developer = runner.invoke(
        registry_admin_app,
        ["revoke-developer", "--client-id", "team-a", "--db-path", str(db_path)],
    )
    assert revoked_developer.exit_code == 0

    backup_path = tmp_path / "admin-backup.sqlite3"
    backed_up = runner.invoke(
        registry_admin_app,
        ["db", "backup", "--output", str(backup_path), "--db-path", str(db_path)],
    )
    assert backed_up.exit_code == 0, backed_up.output
    assert backup_path.is_file()


def test_registry_run_enforces_single_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from agent_auth_registry import run

    called: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> None:
        called.update(kwargs)

    monkeypatch.setattr(run.uvicorn, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["agent-auth-registry", "--port", "8123"])
    run.main()
    assert called["port"] == 8123
    assert called["workers"] == 1

    monkeypatch.setattr(sys, "argv", ["agent-auth-registry", "--workers", "2"])
    with pytest.raises(RuntimeError, match="exactly one worker"):
        run.main()


@pytest.mark.anyio
async def test_registry_health_and_legacy_deprecation_headers(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_REGISTRY_DB_PATH", str(tmp_path / "registry.sqlite3"))
    monkeypatch.setenv("AGENT_REGISTRY_PATH", str(tmp_path / "agent.json"))
    monkeypatch.setenv("AGENT_REGISTRY_STRICT_IDENTITIES", "0")
    app = create_registry_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://registry.local") as client:
        assert (await client.get("/health/live")).json() == {"status": "ok"}
        assert (await client.get("/health/ready")).status_code == 200
        assert (await client.get("/healthz")).status_code == 200
        assert (await client.get("/.well-known/agent.json")).status_code == 200
        legacy = await client.post("/registry/agents/publish", json={})
    assert legacy.status_code == 422
    assert legacy.headers["deprecation"] == "true"
    assert legacy.headers["sunset"]
    assert "/v1/agents/publish" in legacy.headers["link"]
