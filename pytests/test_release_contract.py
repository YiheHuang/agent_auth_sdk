from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_distribution_and_public_surface_are_minimal() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == ["cryptography>=43.0.0", "httpx>=0.27.0"]
    assert project["optional-dependencies"]["openai"] == ["openai-agents>=0.18.2,<0.19"]
    registry = tomllib.loads((ROOT / "packages/agent-auth-registry/pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert registry["version"] == project["version"] == "1.0.0"
    assert registry["dependencies"][0] == "verifiable-agent-auth-sdk==1.0.0"


def test_no_legacy_python_namespace_or_public_symbols() -> None:
    assert not list((ROOT / "agent_auth_sdk").rglob("*.py"))
    import agent_auth

    assert agent_auth.__all__ == ["AgentAuth", "AuthContext", "AgentAuthError", "__version__"]
    for removed in (
        "AgentInstance",
        "AgentVerifier",
        "RegistryClient",
        "RemoteAgentClient",
        "AgentAuthRouter",
        "AuthorizationPolicy",
    ):
        assert not hasattr(agent_auth, removed)
    public_agent_auth = {name for name in dir(agent_auth.AgentAuth) if not name.startswith("_")}
    assert public_agent_auth == {
        "bind",
        "close",
        "endpoint",
        "remote_tool",
        "router",
        "run",
        "run_streamed",
        "run_sync",
    }


def test_documentation_links_and_examples_exist() -> None:
    required = [
        ROOT / "README.md",
        ROOT / "QUICKSTART.md",
        ROOT / "docs/API_REFERENCE.md",
        ROOT / "docs/OPENAI_AGENTS.md",
        ROOT / "docs/PROTOCOL_V1.md",
        ROOT / "docs/SECURITY_MODEL.md",
        ROOT / "docs/REGISTRY_OPERATIONS.md",
        ROOT / "examples/openai_local.py",
        ROOT / "examples/vault_registry.py",
        ROOT / "examples/remote_server.py",
        ROOT / "examples/remote_client.py",
    ]
    assert all(path.is_file() for path in required)
    for document in required[:7]:
        text = document.read_text(encoding="utf-8")
        assert "agent_auth_sdk." not in text
        assert "from agent_auth_sdk" not in text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    links = re.findall(r"\[[^]]+\]\((https://github\.com/YiheHuang/agent_auth_sdk/[^)]+)\)", readme)
    assert len(links) >= 6


def test_examples_do_not_embed_secrets_and_import_only_public_root() -> None:
    forbidden = (
        "sk-",
        "hvs.",
        "Huang" + "2005",
        "BEGIN " + "PRIVATE KEY",
        "AGENT_AUTH_REGISTRY_API_KEY=",
    )
    for path in (ROOT / "examples").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not any(secret in text for secret in forbidden)
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("agent_auth"):
                assert node.module == "agent_auth"
