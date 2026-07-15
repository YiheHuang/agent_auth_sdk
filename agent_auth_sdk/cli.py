"""Developer CLI for Agent Auth SDK."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any, cast

import typer

app = typer.Typer(help="Agent Auth SDK developer tools")
openai_app = typer.Typer(help="Inspect and migrate existing OpenAI Agents projects.")
app.add_typer(openai_app, name="openai")


@app.callback()
def _main() -> None:
    """Agent Auth SDK developer tools."""


@app.command("init")
def init_project(
    project_root: Annotated[Path, typer.Option(help="Project root.")] = Path("."),
    roles: Annotated[str, typer.Option(help="Comma-separated Agent roles.")] = "agent",
    framework: Annotated[str, typer.Option(help="Framework name.")] = "openai-agents",
    mode: Annotated[str, typer.Option(help="Integration mode: local or vault.")] = "local",
    domain: Annotated[str, typer.Option(help="Agent identity domain.")] = "127.0.0.1:8700",
    organization: Annotated[str, typer.Option(help="Organization name.")] = "Agent Auth Application",
) -> None:
    """初始化一个显式 Agent 认证集成。"""

    if framework != "openai-agents":
        raise typer.BadParameter("--framework currently supports only openai-agents")
    integrate_openai_agents(
        project_root=project_root,
        roles=roles,
        mode=mode,
        domain=domain,
        organization=organization,
        registry_url=None,
        registry_publish_url=None,
        role_capability=None,
    )


@app.command("doctor")
def doctor(
    config_path: Annotated[Path, typer.Option("--config", help="Path to agent-auth.toml.")] = Path(
        ".agent-auth/agent-auth.toml"
    ),
) -> None:
    """只读检查配置、identity、Vault token 文件和 Registry TLS 策略。"""

    from .config import get_runtime_profile
    from .identity import build_agent_id
    from .integrations.openai_agents import OpenAIAgentsAuthConfig

    config = OpenAIAgentsAuthConfig.from_file(config_path)
    profile = get_runtime_profile(config.profile)
    checks: dict[str, str] = {}
    for role in config.roles:
        checks[f"identity:{role}"] = build_agent_id(config.domain, role)
    if profile.allow_http is False:
        for name, value in {
            "registry.url": config.registry_url,
            "registry.publish_url": config.registry_publish_url,
            "vault.addr": config.vault_addr,
        }.items():
            if value and not value.startswith("https://"):
                raise typer.BadParameter(f"{name} must use https in strict profile")
    if config.mode == "vault":
        if not config.vault_token_file:
            raise typer.BadParameter("vault.token_file is required in vault mode")
        token_path = Path(config.vault_token_file)
        if not token_path.is_file():
            raise typer.BadParameter(f"Vault token file does not exist: {token_path}")
        checks["vault.token_file"] = "readable"
    checks["profile"] = profile.name
    checks["mode"] = config.mode
    typer.echo(json.dumps({"ok": True, "checks": checks}, ensure_ascii=False, indent=2))


@app.command("provision")
def provision_identity(
    identity: Annotated[str | None, typer.Option(help="Configured role or full Agent ID.")] = None,
    config_path: Annotated[Path, typer.Option("--config", help="Path to agent-auth.toml.")] = Path(
        ".agent-auth/agent-auth.toml"
    ),
) -> None:
    """显式创建/检查配置的 Vault key，并将单个身份发布到 Registry。"""

    from .integrations.openai_agents import OpenAIAgentsAuthConfig
    from .integrations.openai_facade import OpenAIAgentAuth

    async def run() -> dict:
        config = OpenAIAgentsAuthConfig.from_file(config_path)
        auth = await OpenAIAgentAuth.from_config(config, identity=identity, provision=True)
        try:
            return {"ok": True, "agent_id": auth.agent.agent_id, "kid": auth.agent.kid}
        finally:
            await auth.__aexit__()

    typer.echo(json.dumps(asyncio.run(run()), ensure_ascii=False, indent=2))


@openai_app.command("inspect")
def inspect_openai(
    project_root: Annotated[Path, typer.Argument(help="Existing OpenAI Agents project root.")] = Path("."),
    json_output: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")] = False,
) -> None:
    """只读识别 Agent、Tool、Handoff、Runner 和 HTTP 边界。"""

    from .openai_migration import migration_report

    report = migration_report(project_root)
    if json_output:
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    findings = cast(list[dict[str, Any]], report["findings"])
    typer.echo(f"Found {len(findings)} OpenAI Agents integration points.")
    for finding in findings:
        typer.echo(f"{finding['path']}:{finding['line']} [{finding['kind']}] {finding['recommendation']}")


@openai_app.command("migrate")
def migrate_openai(
    project_root: Annotated[Path, typer.Argument(help="Existing OpenAI Agents project root.")] = Path("."),
    write: Annotated[bool, typer.Option("--write", help="Write an idempotent migration report.")] = False,
) -> None:
    """预览或写入迁移清单；不猜测身份、不改写业务源码。"""

    from .openai_migration import migration_report, write_migration_report

    if not write:
        typer.echo(json.dumps(migration_report(project_root), ensure_ascii=False, indent=2))
        typer.echo("Dry run only. Re-run with --write to create .agent-auth migration reports.")
        return
    output = write_migration_report(project_root)
    typer.echo(f"Wrote idempotent migration report: {output}")


@app.command("integrate-openai-agents")
def integrate_openai_agents(
    project_root: Annotated[Path, typer.Option(help="Project root where .agent-auth will be created.")],
    roles: Annotated[str, typer.Option(help="Comma-separated role names, e.g. coordinator,security.")],
    mode: Annotated[str, typer.Option(help="Integration mode: local or vault.")] = "local",
    domain: Annotated[str, typer.Option(help="Agent identity domain.")] = "127.0.0.1:8700",
    organization: Annotated[
        str,
        typer.Option(help="Organization name written to agent metadata."),
    ] = "Agent Auth Application",
    registry_url: Annotated[str | None, typer.Option(help="Registry document URL.")] = None,
    registry_publish_url: Annotated[str | None, typer.Option(help="Registry publish endpoint URL.")] = None,
    role_capability: Annotated[
        list[str] | None,
        typer.Option(help="Role capability mapping in role:capability form. Can be repeated."),
    ] = None,
) -> None:
    parsed_roles = tuple(role.strip() for role in roles.split(",") if role.strip())
    if not parsed_roles:
        raise typer.BadParameter("--roles must include at least one role")
    normalized_mode = mode.lower().strip()
    if normalized_mode not in {"local", "vault"}:
        raise typer.BadParameter("--mode must be local or vault")
    from .identity import build_agent_id

    for role in parsed_roles:
        try:
            build_agent_id(domain, role)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    if normalized_mode == "vault":
        for name, value in (("--registry-url", registry_url), ("--registry-publish-url", registry_publish_url)):
            if value and not value.startswith("https://"):
                raise typer.BadParameter(f"{name} must use https in vault mode")

    root = project_root.resolve()
    auth_dir = root / ".agent-auth"
    auth_dir.mkdir(parents=True, exist_ok=True)

    capabilities = {role: f"agent.{role}" for role in parsed_roles}
    for item in role_capability or []:
        role, capability = _parse_role_capability(item)
        if role not in capabilities:
            raise typer.BadParameter(f"Unknown role in --role-capability: {role}")
        capabilities[role] = capability

    (auth_dir / "agent-auth.toml").write_text(
        _render_config(
            roles=parsed_roles,
            mode=normalized_mode,
            domain=domain,
            organization=organization,
            registry_url=registry_url,
            registry_publish_url=registry_publish_url,
            capabilities=capabilities,
        ),
        encoding="utf-8",
    )
    adapter = _render_adapter()
    (auth_dir / "auth_adapter.py").write_text(adapter, encoding="utf-8")
    importable_adapter = root / "agent_auth_adapter.py"
    if not importable_adapter.exists():
        importable_adapter.write_text(
            adapter.replace(
                'Path(__file__).with_name("agent-auth.toml")',
                'Path(__file__).parent / ".agent-auth" / "agent-auth.toml"',
            ),
            encoding="utf-8",
        )
    (auth_dir / "env.local.example").write_text(_render_local_env(), encoding="utf-8")
    (auth_dir / "env.vault.example").write_text(_render_vault_env(parsed_roles), encoding="utf-8")
    (auth_dir / "INTEGRATION_REPORT.md").write_text(
        _render_report(parsed_roles=parsed_roles, mode=normalized_mode),
        encoding="utf-8",
    )
    typer.echo(f"Generated explicit OpenAI Agents integration in {auth_dir}")
    typer.echo("Generated agent_auth_adapter.py when no file with that name already existed.")
    typer.echo("No existing business source files were modified.")


def _parse_role_capability(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise typer.BadParameter("--role-capability must use role:capability")
    role, capability = value.split(":", 1)
    role = role.strip()
    capability = capability.strip()
    if not role or not capability:
        raise typer.BadParameter("--role-capability must use role:capability")
    return role, capability


def _render_config(
    *,
    roles: tuple[str, ...],
    mode: str,
    domain: str,
    organization: str,
    registry_url: str | None,
    registry_publish_url: str | None,
    capabilities: dict[str, str],
) -> str:
    from .identity import build_agent_id

    scheme = "http" if mode == "local" else "https"
    registry_document = registry_url or f"{scheme}://{domain}/.well-known/agent.json"
    registry_publish = registry_publish_url or f"{scheme}://{domain}/v1/agents/publish"
    single_identity = len(roles) == 1
    lines = [
        f'mode = "{_escape(mode)}"',
        f'domain = "{_escape(domain)}"',
        *(
            [
                f'identity = "{_escape(build_agent_id(domain, roles[0]))}"',
                f'endpoint = "{_escape(scheme)}://{_escape(domain)}/agents/{_escape(roles[0])}"',
                f'public_base_url = "{_escape(scheme)}://{_escape(domain)}"',
            ]
            if single_identity
            else []
        ),
        f'organization = "{_escape(organization)}"',
        f'environment = "{"local" if mode == "local" else "production"}"',
        f'profile = "{"test" if mode == "local" else "strict"}"',
        'runtime_dir = "runtime"',
        *([] if single_identity else ["roles = [" + ", ".join(f'"{_escape(role)}"' for role in roles) + "]"]),
        "",
        "[capabilities]",
        *[f'"{_escape(role)}" = "{_escape(capability)}"' for role, capability in capabilities.items()],
        "",
        "[registry]",
        f'url = "{_escape(registry_document)}"',
        f'publish_url = "{_escape(registry_publish)}"',
        'client_id = "${AGENT_AUTH_REGISTRY_CLIENT_ID}"',
        'api_key = "${AGENT_AUTH_REGISTRY_API_KEY}"',
        "",
        "[vault]",
        'addr = "${AGENT_AUTH_VAULT_ADDR}"',
        'token_file = "${AGENT_AUTH_VAULT_TOKEN_FILE}"',
        'transit_mount = "${AGENT_AUTH_VAULT_TRANSIT_MOUNT}"',
        "auto_create_keys = false",
        "",
        *(
            [
                f'key = "${{AGENT_AUTH_{_env_token(roles[0])}_KEY_NAME}}"',
                "# key_version = 1  # strict deployments should pin this after provisioning",
            ]
            if single_identity
            else [
                "[vault.key_names]",
                *[f'"{_escape(role)}" = "${{AGENT_AUTH_{_env_token(role)}_KEY_NAME}}"' for role in roles],
            ]
        ),
        "",
    ]
    return "\n".join(lines)


def _render_adapter() -> str:
    return """from __future__ import annotations

from pathlib import Path

from agent_auth_sdk.openai import OpenAIAgentAuth


_AUTH: dict[str, OpenAIAgentAuth] = {}


async def get_auth(identity: str | None = None) -> OpenAIAgentAuth:
    key = identity or "__default__"
    if key not in _AUTH:
        config_path = Path(__file__).with_name("agent-auth.toml")
        _AUTH[key] = await OpenAIAgentAuth.from_env(identity=identity, config_path=config_path)
    return _AUTH[key]


async def close_auth() -> None:
    for auth in _AUTH.values():
        await auth.__aexit__()
    _AUTH.clear()
"""


def _render_local_env() -> str:
    return """# Local mode needs no Vault or registry credentials.
AGENT_AUTH_ENABLED=1
AGENT_AUTH_MODE=local
"""


def _render_vault_env(roles: tuple[str, ...]) -> str:
    lines = [
        "AGENT_AUTH_ENABLED=1",
        "AGENT_AUTH_MODE=vault",
        "AGENT_AUTH_REGISTRY_CLIENT_ID=replace-me",
        "AGENT_AUTH_REGISTRY_API_KEY=replace-me",
        "AGENT_AUTH_VAULT_ADDR=https://vault.example.com",
        "AGENT_AUTH_VAULT_TOKEN_FILE=/secure/path/vault-token.txt",
        "AGENT_AUTH_VAULT_TRANSIT_MOUNT=transit",
        *[f"AGENT_AUTH_{_env_token(role)}_KEY_NAME=agent-auth-{role}" for role in roles],
        "",
    ]
    return "\n".join(lines)


def _render_report(*, parsed_roles: tuple[str, ...], mode: str) -> str:
    first_target = parsed_roles[1] if len(parsed_roles) > 1 else parsed_roles[0]
    first_source = parsed_roles[0]
    get_auth_call = "get_auth()" if len(parsed_roles) == 1 else f'get_auth("{first_source}")'
    return f"""# Agent Auth OpenAI Agents Integration

Generated an explicit integration scaffold for roles: {", ".join(parsed_roles)}.

Mode: `{mode}`

No existing business source files were modified. A new importable `agent_auth_adapter.py`
was generated when that path was available.

## Recommended Change

Before (typical Agent-as-tool):

```python
{first_target}_tool = {first_target}.as_tool(
    tool_name="run_{first_target}",
    tool_description="Call {first_target}.",
)
```

After:

```python
from agent_auth_adapter import get_auth

auth = await {get_auth_call}
auth.bind({{"{first_target}": {first_target}}})
{first_target}_tool = auth.agent_as_tool(
    {first_target},
    tool_name="run_{first_target}",
    tool_description="Call the authenticated {first_target} Agent.",
)
{first_source}.tools.append({first_target}_tool)
```

Place the binding and tool creation once during application startup.
"""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _env_token(role: str) -> str:
    return role.upper().replace("-", "_").replace(".", "_")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
