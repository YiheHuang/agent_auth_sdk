"""厂商可直接使用的命令行工具。"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

import httpx
import typer
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

from .config import MetadataResolverConfig, VerificationConfig, get_runtime_profile
from .crypto import LocalPemSigner, generate_ed25519_keypair, public_key_to_base64url
from .metadata import resolve_agent
from .models import AgentKey, AgentMetadata
from .publish import export_well_known, publish_to_registry, render_agent_metadata
from .signing import sign_http_request
from .stores import FileMetadataCache, InMemoryNonceStore
from .verification import verify_http_request

app = typer.Typer(help="Agent Identity SDK CLI")


@app.command("keygen")
def keygen(
    output_dir: Path = typer.Option(Path("runtime/keys"), help="密钥输出目录"),
    kid: str = typer.Option("main", help="生成的 kid"),
) -> None:
    pair = generate_ed25519_keypair(kid=kid)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "private_key.pem").write_text(pair.private_key_pem, encoding="utf-8")
    (output_dir / "public_key.pem").write_text(pair.public_key_pem, encoding="utf-8")
    (output_dir / "public_key.base64url").write_text(pair.public_key_base64url, encoding="utf-8")
    typer.echo(json.dumps(asdict(pair), ensure_ascii=False, indent=2))


@app.command("render-metadata")
def render_metadata_command(
    host: str = typer.Option(..., help="Agent 对外 host，例如 127.0.0.1:8010"),
    agent_name: str = typer.Option(..., help="Agent 名称"),
    organization: str = typer.Option("Demo Org"),
    endpoint: str = typer.Option(..., help="Agent 业务 endpoint"),
    public_key_pem_path: Path = typer.Option(..., exists=True),
    output_dir: Path = typer.Option(Path("runtime")),
    kid: str = typer.Option("main"),
    profile: str = typer.Option("test"),
) -> None:
    from .identity import build_agent_id

    public_key_pem = public_key_pem_path.read_text(encoding="utf-8")
    metadata = render_agent_metadata(
        agent_id=build_agent_id(host, agent_name),
        domain=host,
        name=agent_name,
        organization=organization,
        endpoint=endpoint,
        capabilities=["agent-auth"],
        keys=[
            AgentKey(
                kid=kid,
                public_key_pem=public_key_pem,
                public_key_base64url=public_key_to_base64url(public_key_pem),
                status="active",
            )
        ],
        environment=profile,
        signing_policy={"canonical_request": "v1"},
        verification_policy={"profile": profile},
    )
    target = export_well_known(metadata, output_dir)
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
    private_key_path: Path = typer.Option(..., exists=True),
    kid: str = typer.Option("main"),
    body: str = typer.Option("{}", help="请求体 JSON 字符串"),
) -> None:
    async def _run() -> None:
        signer = LocalPemSigner(private_key_pem=private_key_path.read_text(encoding="utf-8"), kid_value=kid)
        signed = await sign_http_request(
            method=method,
            url=url,
            body=body,
            agent_id=agent_id,
            signer=signer,
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
    registry_url: str = typer.Option(
        "http://192.144.228.237/registry/agents",
        help="中心注册接口地址",
    ),
    publisher: str = typer.Option(None, help="发布方标识"),
    token: str = typer.Option(None, help="注册中心 bearer token"),
) -> None:
    async def _run() -> None:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        result = await publish_to_registry(
            AgentMetadata.model_validate(metadata),
            registry_url=registry_url,
            publisher=publisher,
            token=token,
        )
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
