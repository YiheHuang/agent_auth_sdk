"""唯一 agent-auth.toml 配置。"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ._errors import AgentAuthError
from ._identity import (
    parse_agent_id,
    validate_endpoint,
    validate_local_identity,
    validate_loopback_url,
    validate_service_url,
)

_ENV = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


@dataclass(slots=True, frozen=True)
class VaultSettings:
    url: str
    mount: str = "transit"
    verify: bool | str = True
    namespace: str | None = None


@dataclass(slots=True, frozen=True)
class IdentitySettings:
    alias: str
    agent_id: str
    endpoint: str
    key: str | None
    key_version: int | None
    token_file: Path | None
    capabilities: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class Settings:
    path: Path
    mode: Literal["dev", "local", "production"]
    registry: str | None
    state: Path
    client_id: str | None
    vault: VaultSettings | None
    agents: dict[str, IdentitySettings]
    remotes: dict[str, str]

    @property
    def strict(self) -> bool:
        return self.mode == "production"

    @property
    def uses_vault(self) -> bool:
        return self.mode in {"local", "production"}

    @classmethod
    def load(cls, path: str | Path | None = None) -> Settings:
        configured = path or os.getenv("AGENT_AUTH_CONFIG") or "agent-auth.toml"
        config_path = Path(configured).resolve()
        try:
            raw = _expand(tomllib.loads(config_path.read_text(encoding="utf-8")))
        except FileNotFoundError as exc:
            raise AgentAuthError("CONFIG_NOT_FOUND", f"Configuration file not found: {config_path}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise AgentAuthError("CONFIG_INVALID", "agent-auth.toml is invalid") from exc
        if raw.get("version") != 1:
            raise AgentAuthError("CONFIG_INVALID", "Configuration version must be 1")
        mode = str(raw.get("mode", "production"))
        if mode not in {"dev", "local", "production"}:
            raise AgentAuthError("CONFIG_INVALID", "mode must be dev, local or production")
        strict = mode == "production"
        registry_value = raw.get("registry")
        registry: str | None
        if registry_value and mode == "local":
            registry = validate_loopback_url(str(registry_value))
        else:
            registry = validate_service_url(str(registry_value), strict=strict) if registry_value else None
        if mode in {"local", "production"} and not registry:
            raise AgentAuthError("CONFIG_INVALID", f"{mode} mode requires registry")
        state_value = Path(str(raw.get("state", ".agent-auth/state.sqlite3")))
        state = state_value if state_value.is_absolute() else config_path.parent / state_value
        vault_raw = raw.get("vault")
        vault: VaultSettings | None = None
        if isinstance(vault_raw, dict):
            verify: bool | str = vault_raw.get("verify", True)  # type: ignore[assignment]
            if isinstance(verify, str):
                verify_path = Path(verify)
                verify = str(verify_path if verify_path.is_absolute() else config_path.parent / verify_path)
            vault_url = str(vault_raw.get("url", ""))
            vault = VaultSettings(
                url=(
                    validate_loopback_url(vault_url)
                    if mode == "local"
                    else validate_service_url(vault_url, strict=strict)
                ),
                mount=str(vault_raw.get("mount", "transit")).strip("/"),
                verify=verify,
                namespace=str(vault_raw["namespace"]) if vault_raw.get("namespace") else None,
            )
        if mode in {"local", "production"} and vault is None:
            raise AgentAuthError("CONFIG_INVALID", f"{mode} mode requires [vault]")
        agents_raw = raw.get("agents")
        if not isinstance(agents_raw, dict) or not agents_raw:
            raise AgentAuthError("CONFIG_INVALID", "At least one [agents.<alias>] entry is required")
        agents: dict[str, IdentitySettings] = {}
        for alias, item in agents_raw.items():
            if not isinstance(item, dict):
                raise AgentAuthError("CONFIG_INVALID", f"agents.{alias} must be a table")
            agent_id = str(item.get("id", ""))
            endpoint = str(item.get("endpoint", ""))
            parse_agent_id(agent_id, strict=strict)
            if mode == "local":
                validate_local_identity(agent_id, endpoint)
            else:
                validate_endpoint(agent_id, endpoint, strict=strict)
            version = int(item["key_version"]) if item.get("key_version") is not None else None
            key = str(item["key"]) if item.get("key") else None
            token_file = Path(str(item["token_file"])) if item.get("token_file") else None
            if token_file is not None and not token_file.is_absolute():
                token_file = config_path.parent / token_file
            capabilities = item.get("capabilities", [])
            if not isinstance(capabilities, list) or not all(isinstance(value, str) for value in capabilities):
                raise AgentAuthError("CONFIG_INVALID", f"agents.{alias}.capabilities must be a string list")
            if mode in {"local", "production"} and (not key or not version or version <= 0):
                raise AgentAuthError(
                    "CONFIG_INVALID", f"agents.{alias} requires key and positive key_version in {mode} mode"
                )
            agents[str(alias)] = IdentitySettings(
                alias=str(alias),
                agent_id=agent_id,
                endpoint=endpoint,
                key=key,
                key_version=version,
                token_file=token_file,
                capabilities=tuple(capabilities),
            )
        remotes_raw = raw.get("remotes", {})
        if not isinstance(remotes_raw, dict):
            raise AgentAuthError("CONFIG_INVALID", "remotes must be a table")
        remotes: dict[str, str] = {}
        for alias, agent_id in remotes_raw.items():
            remote_id = str(agent_id)
            parse_agent_id(remote_id, strict=strict)
            if mode == "local" and not remote_id.startswith("agent://localhost/"):
                raise AgentAuthError("INVALID_LOCAL_IDENTITY", "local mode remotes must use agent://localhost/...")
            remotes[str(alias)] = remote_id
        return cls(
            path=config_path,
            mode=mode,  # type: ignore[arg-type]
            registry=registry,
            state=state,
            client_id=str(raw["client_id"]) if raw.get("client_id") else None,
            vault=vault,
            agents=agents,
            remotes=remotes,
        )


def _expand(value: Any) -> Any:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise AgentAuthError("CONFIG_ENV_MISSING", f"Environment variable {name} is not set")
            return os.environ[name]

        return _ENV.sub(replace, value)
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand(item) for item in value]
    return value
