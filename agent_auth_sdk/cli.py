"""厂商可直接使用的命令行工具。"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
import typer
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

from .agent import AgentInstance
from .config import MetadataResolverConfig, VerificationConfig, get_runtime_profile
from .metadata import resolve_agent
from .models import AgentKey, AgentMetadata
from .publish import export_well_known, publish_to_registry
from .registry_security import sign_registry_publish_request
from .signing import sign_http_request
from .stores import FileMetadataCache, InMemoryNonceStore
from .vault_kms import (
    VaultKmsConfig,
    create_vault_key_if_missing,
    resolve_vault_public_key,
    validate_vault_key,
)
from .verification import verify_http_request

app = typer.Typer(help="Agent Identity SDK CLI")


def _resolve_secret(value: str | None, env_name: str | None, label: str) -> str:
    if value:
        return value
    if env_name:
        env_value = os.getenv(env_name)
        if env_value:
            return env_value
    hint = f" or set {env_name}" if env_name else ""
    raise typer.BadParameter(f"{label} is required; pass the explicit option{hint}")


def _vault_verify(ca_cert: str | None, skip_verify: bool) -> bool | str:
    if skip_verify:
        return False
    return ca_cert or True


def _vault_config(
    vault_addr: str,
    vault_token: str,
    transit_mount: str,
    key_name: str,
    vault_namespace: str | None,
    vault_ca_cert: str | None,
    vault_skip_verify: bool,
    kid: str | None = None,
) -> VaultKmsConfig:
    return VaultKmsConfig(
        vault_addr=vault_addr,
        vault_token=vault_token,
        transit_mount=transit_mount,
        key_name=key_name,
        namespace=vault_namespace,
        verify=_vault_verify(vault_ca_cert, vault_skip_verify),
        kid=kid,
    )


@app.command("vault-create-key")
def vault_create_key(
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    key_name: str = typer.Option(..., help="Vault Transit key name"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    vault_namespace: str | None = typer.Option(None, help="Vault Enterprise namespace"),
    vault_ca_cert: str | None = typer.Option(None, help="Vault CA certificate path"),
    vault_skip_verify: bool = typer.Option(False, help="仅本地调试使用：跳过 TLS 校验"),
) -> None:
    token = _resolve_secret(vault_token, vault_token_env, "vault token")
    created = create_vault_key_if_missing(
        _vault_config(vault_addr, token, transit_mount, key_name, vault_namespace, vault_ca_cert, vault_skip_verify),
    )
    typer.echo(json.dumps({"ok": True, "created": created, "key_name": key_name}, ensure_ascii=False, indent=2))


@app.command("inspect-kms-key")
def inspect_kms_key(
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    key_name: str = typer.Option(..., help="Vault Transit key name"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    vault_namespace: str | None = typer.Option(None),
    vault_ca_cert: str | None = typer.Option(None),
    vault_skip_verify: bool = typer.Option(False),
) -> None:
    token = _resolve_secret(vault_token, vault_token_env, "vault token")
    info = resolve_vault_public_key(
        _vault_config(vault_addr, token, transit_mount, key_name, vault_namespace, vault_ca_cert, vault_skip_verify),
    )
    typer.echo(json.dumps(info.__dict__, ensure_ascii=False, indent=2))


@app.command("validate-kms-key")
def validate_kms_key(
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    key_name: str = typer.Option(..., help="Vault Transit key name"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    vault_namespace: str | None = typer.Option(None),
    vault_ca_cert: str | None = typer.Option(None),
    vault_skip_verify: bool = typer.Option(False),
) -> None:
    token = _resolve_secret(vault_token, vault_token_env, "vault token")
    info = validate_vault_key(
        _vault_config(vault_addr, token, transit_mount, key_name, vault_namespace, vault_ca_cert, vault_skip_verify),
    )
    typer.echo(
        json.dumps(
            {
                "ok": True,
                "key_name": info.key_name,
                "key_type": info.key_type,
                "latest_version": info.latest_version,
                "hash_algorithm": info.hash_algorithm,
                "marshaling_algorithm": info.marshaling_algorithm,
            },
            ensure_ascii=False,
            indent=2,
        ),
    )


@app.command("render-metadata")
def render_metadata_command(
    host: str = typer.Option(..., help="Agent 对外 host，例如 127.0.0.1:8010"),
    agent_name: str = typer.Option(..., help="Agent 名称"),
    organization: str = typer.Option("Demo Org"),
    endpoint: str = typer.Option(..., help="Agent 业务 endpoint"),
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    key_name: str = typer.Option(..., help="Vault Transit key name"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    vault_namespace: str | None = typer.Option(None),
    vault_ca_cert: str | None = typer.Option(None),
    vault_skip_verify: bool = typer.Option(False),
    output_dir: Path = typer.Option(Path("runtime")),
    kid: str | None = typer.Option(None),
    profile: str = typer.Option("test"),
) -> None:
    token = _resolve_secret(vault_token, vault_token_env, "vault token")
    agent = AgentInstance.from_vault(
        domain=host,
        name=agent_name,
        organization=organization,
        endpoint=endpoint,
        vault_addr=vault_addr,
        vault_token=token,
        transit_mount=transit_mount,
        key_name=key_name,
        namespace=vault_namespace,
        verify=_vault_verify(vault_ca_cert, vault_skip_verify),
        capabilities=["agent-auth"],
        environment=profile,
        kid=kid,
    )
    target = export_well_known(agent.metadata, output_dir)
    typer.echo(str(target))


@app.command("inspect-metadata")
def inspect_metadata(
    agent_id: str = typer.Argument(...),
    profile: str = typer.Option("test"),
    registry_url: str | None = typer.Option(None, help="中心注册表 `/.well-known/agent.json` 地址"),
) -> None:
    async def _run() -> None:
        async with httpx.AsyncClient() as client:
            result = await resolve_agent(
                agent_id,
                profile=get_runtime_profile(profile),
                http_client=client,
                cache=FileMetadataCache("runtime/metadata_cache.sqlite3"),
                config=MetadataResolverConfig(
                    profile=get_runtime_profile(profile),
                    registry_url=registry_url,
                ),
            )
            typer.echo(result.metadata.model_dump_json(indent=2))

    asyncio.run(_run())


@app.command("sign-request")
def sign_request_command(
    method: str = typer.Option("POST"),
    url: str = typer.Option(...),
    agent_id: str = typer.Option(...),
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    key_name: str = typer.Option(..., help="Vault Transit key name"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    vault_namespace: str | None = typer.Option(None),
    vault_ca_cert: str | None = typer.Option(None),
    vault_skip_verify: bool = typer.Option(False),
    kid: str | None = typer.Option(None),
    body: str = typer.Option("{}", help="请求体 JSON 字符串"),
) -> None:
    async def _run() -> None:
        token = _resolve_secret(vault_token, vault_token_env, "vault token")
        agent = AgentInstance.from_vault(
            domain=__import__("urllib.parse").parse.urlparse(url).netloc,
            name=agent_id.rsplit("/", 1)[-1],
            organization="CLI",
            endpoint=url,
            vault_addr=vault_addr,
            vault_token=token,
            transit_mount=transit_mount,
            key_name=key_name,
            namespace=vault_namespace,
            verify=_vault_verify(vault_ca_cert, vault_skip_verify),
            kid=kid,
        )
        signed = await sign_http_request(
            method=method,
            url=url,
            body=body,
            agent_id=agent_id,
            signer=agent.signer,
        )
        typer.echo(json.dumps(signed.headers, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command("verify-request")
def verify_request_command(
    method: str = typer.Option("POST"),
    url: str = typer.Option(...),
    headers_path: Path = typer.Option(..., exists=True),
    body: str = typer.Option("{}"),
    profile: str = typer.Option("test"),
    registry_url: str | None = typer.Option(None, help="中心注册表 `/.well-known/agent.json` 地址"),
) -> None:
    async def _run() -> None:
        headers = json.loads(headers_path.read_text(encoding="utf-8"))
        async with httpx.AsyncClient() as client:
            result = await verify_http_request(
                method=method,
                url=url,
                headers=headers,
                body=body,
                nonce_store=InMemoryNonceStore(),
                http_client=client,
                cache=FileMetadataCache("runtime/metadata_cache.sqlite3"),
                config=VerificationConfig(profile=get_runtime_profile(profile)),
                resolver_config=MetadataResolverConfig(
                    profile=get_runtime_profile(profile),
                    registry_url=registry_url,
                ),
            )
            payload = {
                "ok": result.ok,
                "code": getattr(result, "code", None),
                "reason": getattr(result, "reason", None),
                "agent_id": getattr(result, "agent_id", None),
                "kid": getattr(result, "kid", None),
                "request_id": getattr(result, "request_id", None),
                "canonical": getattr(result, "canonical", None),
                "metadata": result.metadata.model_dump(mode="json") if getattr(result, "metadata", None) else None,
            }
            typer.echo(json.dumps(payload, ensure_ascii=False, indent=2, default=str))

    asyncio.run(_run())


@app.command("serve-well-known")
def serve_well_known(
    metadata_dir: Path = typer.Option(Path("runtime"), help="包含 .well-known/agent.json 的目录"),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8011),
) -> None:
    app_ = FastAPI()
    agent_json_path = metadata_dir / ".well-known" / "agent.json"

    @app_.get("/.well-known/agent.json")
    async def get_agent_json() -> JSONResponse:
        return JSONResponse(json.loads(agent_json_path.read_text(encoding="utf-8")))

    uvicorn.run(app_, host=host, port=port)


@app.command("publish-to-registry")
def publish_to_registry_command(
    metadata_path: Path = typer.Option(..., exists=True, help="本地 metadata 文件路径"),
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    key_name: str = typer.Option(..., help="Vault Transit key name"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    vault_namespace: str | None = typer.Option(None),
    vault_ca_cert: str | None = typer.Option(None),
    vault_skip_verify: bool = typer.Option(False),
    registry_url: str = typer.Option("http://192.144.228.237/registry/agents/publish", help="中心注册接口地址"),
    client_id: str = typer.Option(..., help="开发者 client_id"),
    api_key: str | None = typer.Option(None, help="显式 developer api key"),
    api_key_env: str = typer.Option("AGENT_AUTH_REGISTRY_API_KEY", help="developer api key 环境变量名"),
    kid: str | None = typer.Option(None),
) -> None:
    async def _run() -> None:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        resolved_api_key = _resolve_secret(api_key, api_key_env, "developer api key")
        token = _resolve_secret(vault_token, vault_token_env, "vault token")
        agent = AgentInstance.from_vault(
            domain=metadata["domain"],
            name=metadata["name"],
            organization=metadata["organization"],
            endpoint=metadata["endpoint"],
            vault_addr=vault_addr,
            vault_token=token,
            transit_mount=transit_mount,
            key_name=key_name,
            namespace=vault_namespace,
            verify=_vault_verify(vault_ca_cert, vault_skip_verify),
            capabilities=metadata.get("capabilities", []),
            environment=metadata.get("environment"),
            kid=kid or metadata["keys"][0]["kid"],
        )
        result = await publish_to_registry(
            AgentMetadata.model_validate(metadata),
            registry_url=registry_url,
            client_id=client_id,
            api_key=resolved_api_key,
            signer=agent.signer,
        )
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command("rotate-key")
def rotate_key_command(
    registry_url: str = typer.Option("http://192.144.228.237/registry/agents/rotate-key"),
    agent_id: str = typer.Option(...),
    vault_addr: str = typer.Option(..., help="Vault address，例如 http://127.0.0.1:8200"),
    vault_token: str | None = typer.Option(None, help="Vault token"),
    vault_token_env: str = typer.Option("VAULT_TOKEN", help="Vault token 环境变量名"),
    transit_mount: str = typer.Option("transit", help="Vault Transit mount path"),
    current_kms_key_id: str = typer.Option(..., help="当前 Vault Transit key name"),
    new_kms_key_id: str = typer.Option(..., help="新的 Vault Transit key name"),
    client_id: str = typer.Option(...),
    api_key: str | None = typer.Option(None),
    api_key_env: str = typer.Option("AGENT_AUTH_REGISTRY_API_KEY"),
    current_kid: str | None = typer.Option(None),
    new_kid: str | None = typer.Option(None),
    vault_namespace: str | None = typer.Option(None),
    vault_ca_cert: str | None = typer.Option(None),
    vault_skip_verify: bool = typer.Option(False),
) -> None:
    async def _run() -> None:
        resolved_api_key = _resolve_secret(api_key, api_key_env, "developer api key")
        token = _resolve_secret(vault_token, vault_token_env, "vault token")
        current_signer = AgentInstance.from_vault(
            domain=agent_id.split("://", 1)[1].split("/", 1)[0],
            name=agent_id.rsplit("/", 1)[-1],
            organization="CLI",
            endpoint="https://placeholder.invalid/invoke",
            vault_addr=vault_addr,
            vault_token=token,
            transit_mount=transit_mount,
            key_name=current_kms_key_id,
            namespace=vault_namespace,
            verify=_vault_verify(vault_ca_cert, vault_skip_verify),
            kid=current_kid,
        )
        next_key = resolve_vault_public_key(
            _vault_config(
                vault_addr,
                token,
                transit_mount,
                new_kms_key_id,
                vault_namespace,
                vault_ca_cert,
                vault_skip_verify,
                new_kid,
            ),
        )
        payload = {
            "agent_id": agent_id,
            "new_key": AgentKey(
                kid=new_kid or f"vault:{transit_mount}/{new_kms_key_id}",
                alg="ES256",
                public_key_pem=next_key.public_key_pem,
                public_key_base64url=next_key.public_key_base64url,
                status="active",
            ).model_dump(mode="json"),
        }
        parsed = urlparse(registry_url)
        signed = await sign_registry_publish_request(
            path=parsed.path or "/",
            host=parsed.netloc,
            body=payload,
            agent_id=agent_id,
            client_id=client_id,
            signer=current_signer.signer,
        )
        headers = dict(signed.headers)
        headers["authorization"] = f"Bearer {resolved_api_key}"
        async with httpx.AsyncClient() as client:
            response = await client.post(registry_url, json=payload, headers=headers)
            response.raise_for_status()
            typer.echo(json.dumps(response.json(), ensure_ascii=False, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
