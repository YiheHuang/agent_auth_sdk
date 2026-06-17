"""Registry 管理 CLI：developer 凭证与 ownership 查询。"""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import asdict
from pathlib import Path

import typer

from agent_auth_sdk.registry_security import hash_api_key

from .app import load_registry_db_path, load_registry_public_path
from .storage import RegistryStore


app = typer.Typer(help="Agent Auth Registry admin CLI")


@app.command("create-developer")
def create_developer(
    client_id: str = typer.Option(..., help="开发者 client_id"),
    db_path: Path = typer.Option(None, help="registry sqlite 路径"),
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
    db_path: Path = typer.Option(None, help="registry sqlite 路径"),
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    payload = [asdict(record) for record in store.list_developers()]
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@app.command("revoke-developer")
def revoke_developer(
    client_id: str = typer.Option(..., help="要吊销的 client_id"),
    db_path: Path = typer.Option(None, help="registry sqlite 路径"),
) -> None:
    store = RegistryStore(db_path or load_registry_db_path())
    store.revoke_developer(client_id=client_id)
    typer.echo(json.dumps({"ok": True, "client_id": client_id}, ensure_ascii=False, indent=2))


@app.command("revoke-agent")
def revoke_agent(
    agent_id: str = typer.Option(..., help="要撤销的 agent_id"),
    db_path: Path = typer.Option(None, help="registry sqlite 路径"),
) -> None:
    """撤销 Agent，将其从公开文档移除，并拒绝后续所有操作。"""
    store = RegistryStore(db_path or load_registry_db_path())
    store.revoke_agent(agent_id=agent_id)
    store.write_public_document(load_registry_public_path())
    typer.echo(json.dumps({"ok": True, "agent_id": agent_id}, ensure_ascii=False, indent=2))


@app.command("inspect-agent")
def inspect_agent(
    agent_id: str = typer.Option(..., help="要查询的 agent_id"),
    db_path: Path = typer.Option(None, help="registry sqlite 路径"),
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
