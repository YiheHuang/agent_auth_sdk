from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
from pathlib import Path

import agent_auth_sdk
import agent_auth_sdk.integrations as integrations

ROOT = Path(__file__).parents[1]


def _run_module(module: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        env=env,
    )


def test_local_examples_execute() -> None:
    message = _run_module("examples.local_signed_message")
    assert message.returncode == 0, message.stderr
    assert "NONCE_REPLAYED" in message.stdout
    assert "SIGNATURE_INVALID" in message.stdout

    http = _run_module("examples.local_http_signing")
    assert http.returncode == 0, http.stderr
    assert "verified: True" in http.stdout
    assert "SIGNATURE_INVALID" in http.stdout


def test_openai_offline_example_executes() -> None:
    result = _run_module("examples.openai_agents.offline_local")
    assert result.returncode == 0, result.stderr
    assert "authenticated offline result" in result.stdout
    assert "call_security_agent" in result.stdout


def test_infrastructure_examples_import_without_side_effects(monkeypatch) -> None:
    for name in list(__import__("os").environ):
        if name.startswith("AGENT_AUTH_") or name == "OPENAI_API_KEY":
            monkeypatch.delenv(name, raising=False)
    for module in (
        "examples.vault_registry_quickstart",
        "examples.key_lifecycle",
        "examples.remote_agent.receiver",
        "examples.remote_agent.sender",
        "examples.openai_agents.live_local",
        "examples.openai_agents.remote_server",
        "examples.openai_agents.remote_client",
    ):
        importlib.import_module(module)


def test_infrastructure_script_help_does_not_require_credentials() -> None:
    cases = (
        ("examples.vault_registry_quickstart", "--help"),
        ("examples.key_lifecycle", "--help"),
        ("examples.remote_agent.sender", "--help"),
        ("examples.openai_agents.live_local", "--help"),
        ("examples.openai_agents.remote_client", "--help"),
    )
    for module, arg in cases:
        result = _run_module(module, arg)
        assert result.returncode == 0, f"{module}: {result.stderr}"
        assert "usage:" in result.stdout.lower()


def test_documented_api_covers_all_exports() -> None:
    reference = (ROOT / "docs" / "API_REFERENCE.md").read_text(encoding="utf-8")
    for name in (*agent_auth_sdk.__all__, *integrations.__all__):
        assert name in reference, f"public export is undocumented: {name}"


def test_markdown_relative_links_resolve() -> None:
    markdown_files = [ROOT / "README.md", ROOT / "QUICKSTART.md", *sorted((ROOT / "docs").glob("*.md"))]
    pattern = re.compile(r"\[[^]]*]\(([^)]+)\)")
    for document in markdown_files:
        for target in pattern.findall(document.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path_text = target.split("#", 1)[0]
            if not path_text:
                continue
            assert (document.parent / path_text).resolve().exists(), f"broken link in {document}: {target}"


def test_examples_do_not_embed_credentials() -> None:
    forbidden = ("BEGIN PRIVATE KEY", "pypi-", "hvs.", "sk-proj-")
    for path in (ROOT / "examples").rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in content, f"credential-like marker in {path}: {marker}"
