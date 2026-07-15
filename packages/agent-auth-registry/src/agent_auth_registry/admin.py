"""Registry 管理 CLI：developer 凭证与 ownership 查询。"""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

from agent_auth_sdk.identity import normalize_agent_host, normalize_agent_path_prefix
from agent_auth_sdk.registry_security import hash_api_key

from .app import load_registry_db_path, load_registry_public_path
from .storage import RegistryStore

app = typer.Typer(help="Agent Auth Registry admin CLI")
db_app = typer.Typer(help="检查和备份 Registry SQLite 数据库")
app.add_typer(db_app, name="db")


@db_app.command("check")
def check_database(
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    """检查 schema 版本和 SQLite 完整性。"""

    store = RegistryStore(db_path or load_registry_db_path())
    status = store.schema_status()
    typer.echo(json.dumps(status, ensure_ascii=False, indent=2))
    if not status["ok"]:
        raise typer.Exit(code=1)


@db_app.command("backup")
def backup_database(
    output: Annotated[Path, typer.Option("--output", "-o", help="备份文件路径")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    """在线创建一致的 SQLite 备份。"""

    store = RegistryStore(db_path or load_registry_db_path())
    target = store.backup(output)
    typer.echo(json.dumps({"ok": True, "backup": str(target)}, ensure_ascii=False, indent=2))


@app.command("create-developer")
def create_developer(
    client_id: Annotated[str, typer.Option(help="开发者 client_id")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    developer_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)
    store.create_developer(
        developer_id=developer_id,
        client_id=client_id,
        api_key_hash=hash_api_key(api_key),
    )
    typer.echo(
        json.dumps(
            {
                "developer_id": developer_id,
                "client_id": client_id,
                "api_key": api_key,
            },
            ensure_ascii=False,
            indent=2,
        ),
    )


@app.command("list-developers")
def list_developers(
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    payload = [asdict(record) for record in store.list_developers()]
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@app.command("grant-namespace")
def grant_namespace(
    client_id: Annotated[str, typer.Option(help="开发者 client_id")],
    domain: Annotated[str, typer.Option(help="精确匹配的 Agent domain")],
    path_prefix: Annotated[str, typer.Option(help="允许的 agent path 前缀")] = "/",
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    developer = store.get_developer_by_client_id(client_id)
    if developer is None or developer.status != "active":
        raise typer.BadParameter("active developer not found")
    try:
        record = store.create_namespace(
            developer_id=developer.developer_id,
            domain=normalize_agent_host(domain),
            path_prefix=normalize_agent_path_prefix(path_prefix),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(asdict(record), ensure_ascii=False, indent=2))


@app.command("list-namespaces")
def list_namespaces(
    client_id: Annotated[str | None, typer.Option(help="可选的开发者 client_id")] = None,
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    developer_id = None
    if client_id:
        developer = store.get_developer_by_client_id(client_id)
        if developer is None:
            raise typer.BadParameter("developer not found")
        developer_id = developer.developer_id
    payload = [asdict(record) for record in store.list_namespaces(developer_id=developer_id)]
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@app.command("revoke-namespace")
def revoke_namespace(
    namespace_id: Annotated[str, typer.Option(help="要撤销的 namespace id")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    if not store.revoke_namespace(namespace_id=namespace_id):
        raise typer.BadParameter("active namespace not found")
    typer.echo(json.dumps({"ok": True, "namespace_id": namespace_id}, ensure_ascii=False, indent=2))


@app.command("rotate-api-key")
def rotate_api_key(
    client_id: Annotated[str, typer.Option(help="开发者 client_id")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    developer = store.get_developer_by_client_id(client_id)
    if developer is None or developer.status != "active":
        raise typer.BadParameter("active developer not found")
    api_key = secrets.token_urlsafe(32)
    store.update_developer_api_key_hash(client_id=client_id, api_key_hash=hash_api_key(api_key))
    typer.echo(json.dumps({"client_id": client_id, "api_key": api_key}, ensure_ascii=False, indent=2))


@app.command("revoke-developer")
def revoke_developer(
    client_id: Annotated[str, typer.Option(help="要吊销的 client_id")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    store.revoke_developer(client_id=client_id)
    typer.echo(json.dumps({"ok": True, "client_id": client_id}, ensure_ascii=False, indent=2))


@app.command("revoke-agent")
def revoke_agent(
    agent_id: Annotated[str, typer.Option(help="要撤销的 agent_id")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    """撤销 Agent，将其从公开文档移除，并拒绝后续所有操作。"""
    store = RegistryStore(db_path or load_registry_db_path())
    if not store.admin_revoke_agent(agent_id=agent_id):
        raise typer.BadParameter("active Agent not found")
    store.write_public_document(load_registry_public_path())
    typer.echo(json.dumps({"ok": True, "agent_id": agent_id}, ensure_ascii=False, indent=2))


@app.command("inspect-agent")
def inspect_agent(
    agent_id: Annotated[str, typer.Option(help="要查询的 agent_id")],
    db_path: Annotated[Path | None, typer.Option(help="registry sqlite 路径")] = None,
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    ownership = store.get_ownership(agent_id)
    entry = store.get_registry_entry(agent_id)
    typer.echo(
        json.dumps(
            {
                "ownership": asdict(ownership) if ownership else None,
                "entry": asdict(entry) if entry else None,
            },
            ensure_ascii=False,
            indent=2,
        ),
    )


if __name__ == "__main__":
    app()
