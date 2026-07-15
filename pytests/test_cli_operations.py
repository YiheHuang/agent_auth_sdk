from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_auth import AgentAuthError, _cli
from agent_auth._config import IdentitySettings, VaultSettings
from agent_auth._protocol import DevSigner


class MutationRegistry:
    def __init__(self) -> None:
        self.envelopes: list[Any] = []

    async def mutate(self, envelope: Any) -> dict[str, object]:
        self.envelopes.append(envelope)
        return {"kid": envelope.kid}


class FakeVaultSigner:
    rotated = False

    def __init__(self, *, agent_id: str, settings: Any, identity: IdentitySettings) -> None:
        self.identity = identity
        self._signer = DevSigner(agent_id)
        self._signer._kid = f"{agent_id}#key:v{identity.key_version}"

    @property
    def kid(self) -> str:
        return self._signer.kid

    @property
    def public_key(self) -> str:
        return self._signer.public_key

    async def sign(self, data: bytes) -> bytes:
        return await self._signer.sign(data)

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def latest_version(self) -> int:
        return int(self.identity.key_version or 1)

    async def rotate(self) -> int:
        type(self).rotated = True
        return int(self.identity.key_version or 1) + 1


def _auth(tmp_path: Path) -> Any:
    path = tmp_path / "agent-auth.toml"
    path.write_text(
        """version=1
mode="production"
registry="https://registry.example.com"
client_id="team"
[vault]
url="https://vault.example.com"
[agents.agent]
id="agent://agents.example.com/agent"
endpoint="https://agents.example.com/invoke"
key="agent"
key_version=1
""",
        encoding="utf-8",
    )
    identity = IdentitySettings(
        alias="agent",
        agent_id="agent://agents.example.com/agent",
        endpoint="https://agents.example.com/invoke",
        key="agent",
        key_version=1,
        token_file=None,
        capabilities=("work",),
    )
    current = FakeVaultSigner(
        agent_id=identity.agent_id,
        settings=VaultSettings("https://vault.example.com"),
        identity=identity,
    )
    return SimpleNamespace(
        _settings=SimpleNamespace(
            agents={"agent": identity},
            registry="https://registry.example.com",
            vault=VaultSettings("https://vault.example.com"),
            path=path,
        ),
        _signers={"agent": current},
        _registry=MutationRegistry(),
    )


def test_publish_rotate_revoke_and_atomic_config_update(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        auth = _auth(tmp_path)
        monkeypatch.setattr(_cli, "VaultSigner", FakeVaultSigner)
        published = await _cli._publish(auth, "agent")
        assert published["agent_id"] == auth._settings.agents["agent"].agent_id
        rotated = await _cli._rotate(auth, "agent")
        assert rotated["key_version"] == 2
        assert FakeVaultSigner.rotated
        assert "key_version = 2" in auth._settings.path.read_text(encoding="utf-8")
        await _cli._revoke(auth, "agent")
        assert [item.type for item in auth._registry.envelopes] == [
            "registry.publish",
            "registry.rotate",
            "registry.revoke",
        ]

    asyncio.run(scenario())


def test_cli_operation_errors_are_stable(tmp_path) -> None:
    auth = _auth(tmp_path)
    with pytest.raises(AgentAuthError, match="IDENTITY_NOT_CONFIGURED"):
        _cli._identity(auth, "missing")
    auth._settings.registry = None
    with pytest.raises(AgentAuthError, match="REGISTRY_UNAVAILABLE"):
        _cli._registry_audience(auth)
    auth = _auth(tmp_path)
    auth._signers["agent"] = DevSigner(auth._settings.agents["agent"].agent_id)
    with pytest.raises(AgentAuthError, match="ROTATE_REQUIRES_VAULT"):
        asyncio.run(_cli._rotate(auth, "agent"))


def test_update_key_version_adds_missing_field(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[agents.a]\nkey='a'\n", encoding="utf-8")
    _cli._update_key_version(path, "a", 3)
    assert "key_version = 3" in path.read_text(encoding="utf-8")
    with pytest.raises(AgentAuthError, match="CONFIG_UPDATE_FAILED"):
        _cli._update_key_version(path, "missing", 2)
