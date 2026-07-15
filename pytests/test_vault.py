from __future__ import annotations

import asyncio
import base64
import os
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agent_auth import AgentAuthError
from agent_auth._config import IdentitySettings, VaultSettings
from agent_auth._vault import VaultSigner, read_token


def _identity(token_file: Path | None = None) -> IdentitySettings:
    return IdentitySettings(
        alias="agent",
        agent_id="agent://agents.example.com/agent",
        endpoint="https://agents.example.com/invoke",
        key="agent",
        key_version=1,
        token_file=token_file,
        capabilities=(),
    )


def test_vault_signer_reads_key_signs_and_rotates(monkeypatch) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    calls: list[tuple[str, str]] = []
    latest = 1

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal latest
        calls.append((request.method, request.url.path))
        assert request.headers["X-Vault-Token"] == "token"
        if request.url.path.endswith("/rotate"):
            latest = 2
            return httpx.Response(200, json={})
        if "/sign/" in request.url.path:
            data = private_key.sign(b"payload", ec.ECDSA(hashes.SHA256()))
            return httpx.Response(200, json={"data": {"signature": "vault:v1:" + base64.b64encode(data).decode()}})
        return httpx.Response(
            200,
            json={"data": {"latest_version": latest, "keys": {"1": {"public_key": pem}}}},
        )

    async def scenario() -> None:
        monkeypatch.setenv("AGENT_AUTH_VAULT_TOKEN", "token")
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://vault.example.com")
        signer = VaultSigner(
            agent_id=_identity().agent_id,
            settings=VaultSettings("https://vault.example.com"),
            identity=_identity(),
            client=client,
        )
        await signer.start()
        assert signer.kid.endswith("#key:v1")
        assert await signer.sign(b"payload")
        assert await signer.latest_version() == 1
        assert await signer.rotate() == 2
        await signer.close()
        await client.aclose()

    asyncio.run(scenario())
    assert any("/sign/" in path for _, path in calls)


def test_vault_token_file_empty_before_permission_error(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AGENT_AUTH_VAULT_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_AUTH_VAULT_TOKEN_AGENT", raising=False)
    path = tmp_path / "token"
    path.write_text("", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o644)
    with pytest.raises(AgentAuthError, match="VAULT_TOKEN_EMPTY"):
        read_token(_identity(path))
    path.write_text("secret", encoding="utf-8")
    if os.name != "nt":
        with pytest.raises(AgentAuthError, match="VAULT_TOKEN_PERMISSIONS"):
            read_token(_identity(path))
        path.chmod(0o600)
    assert read_token(_identity(path)) == "secret"


def test_vault_errors_are_stable(monkeypatch) -> None:
    async def scenario() -> None:
        monkeypatch.setenv("AGENT_AUTH_VAULT_TOKEN", "token")

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"errors": ["denied"]})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://vault.example.com")
        signer = VaultSigner(
            agent_id=_identity().agent_id,
            settings=VaultSettings("https://vault.example.com"),
            identity=_identity(),
            client=client,
        )
        with pytest.raises(AgentAuthError, match="VAULT_REQUEST_FAILED"):
            await signer.start()
        await client.aclose()

    asyncio.run(scenario())


def test_vault_rejects_missing_configuration_and_uninitialized_access(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_AUTH_VAULT_TOKEN", "token")
    invalid = _identity()
    invalid = IdentitySettings(
        alias=invalid.alias,
        agent_id=invalid.agent_id,
        endpoint=invalid.endpoint,
        key=None,
        key_version=None,
        token_file=None,
        capabilities=(),
    )
    with pytest.raises(AgentAuthError, match="VAULT_CONFIG_INVALID"):
        VaultSigner(agent_id=invalid.agent_id, settings=VaultSettings("https://vault.example.com"), identity=invalid)
    signer = VaultSigner(
        agent_id=_identity().agent_id,
        settings=VaultSettings("https://vault.example.com"),
        identity=_identity(),
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={}))),
    )
    with pytest.raises(AgentAuthError, match="VAULT_NOT_READY"):
        _ = signer.public_key


@pytest.mark.parametrize(
    ("payload", "operation", "code"),
    [
        ({"data": {"keys": {}}}, "start", "VAULT_KEY_VERSION_NOT_FOUND"),
        ({"data": {}}, "sign", "VAULT_RESPONSE_INVALID"),
        ({"data": {"signature": "vault:v2:AAAA"}}, "sign", "VAULT_RESPONSE_INVALID"),
        ({"data": {"signature": "vault:v1:***"}}, "sign", "VAULT_RESPONSE_INVALID"),
        ({"data": {}}, "latest", "VAULT_RESPONSE_INVALID"),
    ],
)
def test_vault_response_validation(monkeypatch, payload, operation: str, code: str) -> None:
    async def scenario() -> None:
        monkeypatch.setenv("AGENT_AUTH_VAULT_TOKEN", "token")
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload)),
            base_url="https://vault.example.com",
        )
        signer = VaultSigner(
            agent_id=_identity().agent_id,
            settings=VaultSettings("https://vault.example.com", namespace="team"),
            identity=_identity(),
            client=client,
        )
        with pytest.raises(AgentAuthError, match=code):
            if operation == "start":
                await signer.start()
            elif operation == "sign":
                await signer.sign(b"payload")
            else:
                await signer.latest_version()
        await client.aclose()

    asyncio.run(scenario())


def test_vault_token_missing_and_unreadable(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AGENT_AUTH_VAULT_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_AUTH_VAULT_TOKEN_AGENT", raising=False)
    with pytest.raises(AgentAuthError, match="VAULT_TOKEN_MISSING"):
        read_token(_identity())
    with pytest.raises(AgentAuthError, match="VAULT_TOKEN_UNREADABLE"):
        read_token(_identity(tmp_path / "missing"))
