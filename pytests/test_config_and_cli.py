from __future__ import annotations

import json
import os

import pytest

from agent_auth import AgentAuthError
from agent_auth._cli import build_parser, main
from agent_auth._config import Settings
from agent_auth._identity import (
    namespace_matches,
    parse_agent_id,
    resolve_public_host,
    validate_endpoint,
    validate_local_identity,
    validate_loopback_url,
    validate_service_url,
)


def test_public_api_is_exact() -> None:
    import agent_auth

    assert agent_auth.__all__ == ["AgentAuth", "AuthContext", "AgentAuthError", "__version__"]


def test_cli_has_exactly_five_commands() -> None:
    parser = build_parser()
    subparsers = next(action for action in parser._actions if action.dest == "command")
    assert set(subparsers.choices) == {"init", "check", "publish", "rotate", "revoke"}


def test_init_and_check_dev_config(tmp_path, capsys) -> None:
    path = tmp_path / "agent-auth.toml"
    assert main(["--config", str(path), "init"]) == 0
    assert main(["--config", str(path), "check"]) == 0
    output = capsys.readouterr().out
    assert '"ok": true' in output
    assert Settings.load(path).mode == "dev"
    assert main(["--config", str(path), "init"]) == 1


def test_config_env_expansion_and_relative_paths(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("REGISTRY_URL", "https://registry.example.com")
    path = tmp_path / "agent-auth.toml"
    path.write_text(
        """version=1
mode="production"
registry="${REGISTRY_URL}"
client_id="team"
[vault]
url="https://vault.example.com"
verify="ca.pem"
[agents.a]
id="agent://agents.example.com/a"
endpoint="https://agents.example.com/a"
key="a"
key_version=1
token_file="token"
""",
        encoding="utf-8",
    )
    settings = Settings.load(path)
    assert settings.registry == "https://registry.example.com"
    assert settings.vault and settings.vault.verify == str(tmp_path / "ca.pem")
    assert settings.agents["a"].token_file == tmp_path / "token"


def test_local_mode_requires_persistent_services_and_loopback(tmp_path) -> None:
    path = tmp_path / "agent-auth.toml"
    path.write_text(
        """version=1
mode="local"
registry="http://127.0.0.1:8010"
state="state.sqlite3"
[vault]
url="http://127.0.0.1:8200"
[agents.a]
id="agent://localhost/demo/a"
endpoint="http://localhost:8101/invoke"
key="demo-a"
key_version=1
token_file="token"
[remotes]
b="agent://localhost/demo/b"
""",
        encoding="utf-8",
    )
    settings = Settings.load(path)
    assert settings.mode == "local"
    assert settings.uses_vault is True
    assert settings.strict is False
    assert settings.state == tmp_path / "state.sqlite3"

    validate_local_identity("agent://localhost/demo/a", "http://localhost:8101/invoke")
    assert validate_loopback_url("http://[::1]:8200/") == "http://[::1]:8200"
    with pytest.raises(AgentAuthError, match="INVALID_LOCAL_URL"):
        validate_loopback_url("https://vault.example.com")


@pytest.mark.parametrize(
    "replacement,code",
    [
        ('registry="https://registry.example.com"', "INVALID_LOCAL_URL"),
        ('id="agent://agents.example.com/demo/a"', "INVALID_LOCAL_IDENTITY"),
        ('endpoint="http://example.com:8101/invoke"', "INVALID_ENDPOINT"),
    ],
)
def test_local_mode_rejects_non_loopback(tmp_path, replacement: str, code: str) -> None:
    content = """version=1
mode="local"
registry="http://127.0.0.1:8010"
[vault]
url="http://127.0.0.1:8200"
[agents.a]
id="agent://localhost/demo/a"
endpoint="http://localhost:8101/invoke"
key="demo-a"
key_version=1
token_file="token"
"""
    if replacement.startswith("registry"):
        content = content.replace('registry="http://127.0.0.1:8010"', replacement)
    elif replacement.startswith("id"):
        content = content.replace('id="agent://localhost/demo/a"', replacement)
    else:
        content = content.replace('endpoint="http://localhost:8101/invoke"', replacement)
    path = tmp_path / "invalid-local.toml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AgentAuthError, match=code):
        Settings.load(path)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/a",
        "agent://user@example.com/a",
        "agent://example.com/a?x=1",
        "agent://example.com/a/",
        "agent://127.0.0.1/a",
        "agent://8.8.8.8/a",
        "agent://localhost.localdomain/a",
        "agent://service.internal/a",
        "agent://singlelabel/a",
    ],
)
def test_strict_agent_id_rejects_ambiguous_or_non_public_values(value: str) -> None:
    with pytest.raises(AgentAuthError, match="INVALID_AGENT_ID"):
        parse_agent_id(value)


def test_identity_endpoint_and_namespace() -> None:
    assert parse_agent_id("agent://agents.example.com/team/a") == ("agents.example.com", ("team", "a"))
    validate_endpoint("agent://agents.example.com/team/a", "https://agents.example.com/invoke")
    assert namespace_matches("agent://agents.example.com/team/a", "agents.example.com", "/team")
    assert not namespace_matches("agent://agents.example.com/other/a", "agents.example.com", "/team")
    with pytest.raises(AgentAuthError, match="INVALID_ENDPOINT"):
        validate_endpoint("agent://agents.example.com/team/a", "https://other.example.com/invoke")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://agents.example.com/invoke",
        "https://user@agents.example.com/invoke",
        "https://agents.example.com/invoke?x=1",
        "ftp://agents.example.com/invoke",
    ],
)
def test_strict_endpoint_rejects_unsafe_forms(endpoint: str) -> None:
    with pytest.raises(AgentAuthError, match="INVALID_ENDPOINT"):
        validate_endpoint("agent://agents.example.com/a", endpoint)


@pytest.mark.parametrize(
    "url",
    ["http://registry.example.com", "https://user@registry.example.com", "https://127.0.0.1"],
)
def test_service_url_strict_validation(url: str) -> None:
    with pytest.raises(AgentAuthError, match="INVALID_URL"):
        validate_service_url(url)
    assert validate_service_url("http://127.0.0.1:8008/", strict=False) == "http://127.0.0.1:8008"


def test_public_dns_resolution_rejects_private_and_errors(monkeypatch) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("8.8.8.8", 0))],
    )
    assert resolve_public_host("example.com") == {"8.8.8.8"}
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(AgentAuthError, match="ENDPOINT_NOT_PUBLIC"):
        resolve_public_host("example.com")

    import socket

    def failed(*_args, **_kwargs):
        raise socket.gaierror

    monkeypatch.setattr("socket.getaddrinfo", failed)
    with pytest.raises(AgentAuthError, match="ENDPOINT_DNS_FAILED"):
        resolve_public_host("example.com")


def test_missing_environment_variable_is_stable(tmp_path) -> None:
    path = tmp_path / "agent-auth.toml"
    path.write_text('version=1\nmode="production"\nregistry="${MISSING_TEST_VALUE}"', encoding="utf-8")
    os.environ.pop("MISSING_TEST_VALUE", None)
    with pytest.raises(AgentAuthError, match="CONFIG_ENV_MISSING"):
        Settings.load(path)


@pytest.mark.parametrize(
    "content",
    [
        "not = [toml",
        'version=2\nmode="dev"',
        'version=1\nmode="other"',
        'version=1\nmode="production"',
        'version=1\nmode="production"\nregistry="https://registry.example.com"',
        'version=1\nmode="dev"\nagents=[]',
        'version=1\nmode="dev"\n[agents]\na="bad"',
        (
            'version=1\nmode="dev"\n[agents.a]\nid="agent://127.0.0.1/a"\n'
            'endpoint="http://127.0.0.1/a"\ncapabilities=[1]'
        ),
        (
            'version=1\nmode="dev"\n[agents.a]\nid="agent://127.0.0.1/a"\n'
            'endpoint="http://127.0.0.1/a"\n[remotes]\na=[1]'
        ),
    ],
)
def test_invalid_configuration_shapes(tmp_path, content: str) -> None:
    path = tmp_path / "invalid.toml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AgentAuthError, match="CONFIG_INVALID|INVALID_AGENT_ID"):
        Settings.load(path)


def test_config_not_found_and_env_override(tmp_path, monkeypatch) -> None:
    with pytest.raises(AgentAuthError, match="CONFIG_NOT_FOUND"):
        Settings.load(tmp_path / "missing.toml")
    path = tmp_path / "configured.toml"
    path.write_text(
        'version=1\nmode="dev"\n[agents.a]\nid="agent://127.0.0.1/a"\nendpoint="http://127.0.0.1/a"',
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_AUTH_CONFIG", str(path))
    assert Settings.load().path == path


def test_error_is_safe_and_structured() -> None:
    error = AgentAuthError("CODE", "safe", request_id="r", agent_id="a", details={"status": 400})
    assert str(error) == "CODE: safe"
    assert json.dumps(error.as_dict(), sort_keys=True) == (
        '{"agent_id": "a", "code": "CODE", "details": {"status": 400}, "message": "safe", "request_id": "r"}'
    )
