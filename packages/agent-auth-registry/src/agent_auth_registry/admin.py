"""Registry 本机管理员 CLI。"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .app import load_db_path
from .security import hash_api_key, new_api_key
from .storage import RegistryStore, StateConflictError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-auth-registry-admin")
    parser.add_argument("--db-path", type=Path, default=None)
    groups = parser.add_subparsers(dest="group", required=True)

    developer = groups.add_parser("developer")
    developer_commands = developer.add_subparsers(dest="command", required=True)
    add = developer_commands.add_parser("add")
    add.add_argument("--client-id", required=True)
    add.add_argument("--domain")
    add.add_argument("--path-prefix", default="/")
    developer_commands.add_parser("list")
    revoke = developer_commands.add_parser("revoke")
    revoke.add_argument("--client-id", required=True)
    rotate = developer_commands.add_parser("rotate-key")
    rotate.add_argument("--client-id", required=True)

    namespace = groups.add_parser("namespace")
    namespace_commands = namespace.add_subparsers(dest="command", required=True)
    grant = namespace_commands.add_parser("grant")
    grant.add_argument("--client-id", required=True)
    grant.add_argument("--domain", required=True)
    grant.add_argument("--path-prefix", required=True)
    listing = namespace_commands.add_parser("list")
    listing.add_argument("--client-id")
    remove = namespace_commands.add_parser("revoke")
    remove.add_argument("--namespace-id", required=True)

    agent = groups.add_parser("agent")
    agent_commands = agent.add_subparsers(dest="command", required=True)
    agent_revoke = agent_commands.add_parser("revoke")
    agent_revoke.add_argument("--agent-id", required=True)

    db = groups.add_parser("db")
    db_commands = db.add_subparsers(dest="command", required=True)
    db_commands.add_parser("check")
    backup = db_commands.add_parser("backup")
    backup.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = RegistryStore(args.db_path or load_db_path())
    try:
        if args.group == "developer":
            return _developer(store, args)
        if args.group == "namespace":
            return _namespace(store, args)
        if args.group == "agent":
            store.admin_revoke_agent(args.agent_id)
            _print({"ok": True, "agent_id": args.agent_id})
            return 0
        if args.command == "check":
            value = store.schema_status()
            _print(value)
            return 0 if value["ok"] else 1
        target = store.backup(args.output)
        _print({"ok": True, "path": str(target)})
        return 0
    except StateConflictError as exc:
        _print({"ok": False, "code": str(exc)})
        return 1


def _developer(store: RegistryStore, args: argparse.Namespace) -> int:
    if args.command == "list":
        _print(
            [
                {"id": value.id, "client_id": value.client_id, "status": value.status}
                for value in store.list_developers()
            ]
        )
        return 0
    if args.command == "revoke":
        store.revoke_developer(args.client_id)
        _print({"ok": True, "client_id": args.client_id})
        return 0
    api_key = new_api_key()
    if args.command == "rotate-key":
        store.rotate_developer_key(args.client_id, hash_api_key(api_key))
        _print({"ok": True, "client_id": args.client_id, "api_key": api_key})
        return 0
    created = store.create_developer(args.client_id, hash_api_key(api_key))
    result: dict[str, object] = {"ok": True, "client_id": args.client_id, "api_key": api_key}
    if args.domain:
        namespace = store.grant_namespace(created.id, args.domain, args.path_prefix)
        result["namespace_id"] = namespace.id
    _print(result)
    return 0


def _namespace(store: RegistryStore, args: argparse.Namespace) -> int:
    if args.command == "list":
        _print(
            [
                {
                    "id": value.id,
                    "developer_id": value.developer_id,
                    "domain": value.domain,
                    "path_prefix": value.path_prefix,
                    "status": value.status,
                }
                for value in store.list_namespaces(args.client_id)
            ]
        )
        return 0
    if args.command == "revoke":
        store.revoke_namespace(args.namespace_id)
        _print({"ok": True, "namespace_id": args.namespace_id})
        return 0
    developer = store.get_developer(args.client_id)
    if developer is None or developer.status != "active":
        raise StateConflictError("DEVELOPER_NOT_FOUND")
    value = store.grant_namespace(developer.id, args.domain, args.path_prefix)
    _print({"ok": True, "namespace_id": value.id})
    return 0


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
