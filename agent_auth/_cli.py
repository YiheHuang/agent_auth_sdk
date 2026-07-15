"""五个命令的 SDK CLI。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import uuid
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from ._auth import AgentAuth
from ._config import Settings
from ._errors import AgentAuthError
from ._protocol import sign_envelope
from ._registry import Registry
from ._vault import VaultSigner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-auth")
    parser.add_argument("--config", type=Path, default=None)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--force", action="store_true")
    commands.add_parser("check")
    publish = commands.add_parser("publish")
    publish.add_argument("alias", nargs="?")
    rotate = commands.add_parser("rotate")
    rotate.add_argument("alias")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("alias")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            return _init(args.config or Path("agent-auth.toml"), force=args.force)
        return asyncio.run(_async_command(args))
    except AgentAuthError as exc:
        print(json.dumps({"ok": False, "error": exc.as_dict()}, ensure_ascii=False, indent=2))
        return 1


async def _async_command(args: argparse.Namespace) -> int:
    if args.command == "check":
        return await _check(args.config)
    auth = AgentAuth(args.config)
    async with auth:
        if args.command == "publish":
            aliases = [args.alias] if args.alias else list(auth._settings.agents)
            results = [await _publish(auth, alias) for alias in aliases]
            _print({"ok": True, "agents": results})
            return 0
        if args.command == "rotate":
            result = await _rotate(auth, args.alias)
            _print({"ok": True, **result})
            return 0
        await _revoke(auth, args.alias)
        _print({"ok": True, "agent_id": auth._settings.agents[args.alias].agent_id})
        return 0


def _init(path: Path, *, force: bool) -> int:
    if path.exists() and not force:
        raise AgentAuthError("CONFIG_EXISTS", f"Configuration already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """version = 1
mode = "dev"
state = ".agent-auth/state.sqlite3"

[agents.agent]
id = "agent://127.0.0.1/agent"
endpoint = "http://127.0.0.1:8000/invoke"
capabilities = []
""",
        encoding="utf-8",
    )
    _print({"ok": True, "config": str(path)})
    return 0


async def _check(path: Path | None) -> int:
    settings = Settings.load(path)
    checks: dict[str, object] = {"mode": settings.mode, "identities": list(settings.agents)}
    if settings.mode == "production":
        if settings.vault is None:  # pragma: no cover - config already enforces
            raise AgentAuthError("VAULT_CONFIG_INVALID", "Vault is required")
        for alias, identity in settings.agents.items():
            signer = VaultSigner(agent_id=identity.agent_id, settings=settings.vault, identity=identity)
            try:
                await signer.start()
                checks[f"vault:{alias}"] = {"kid": signer.kid, "ok": True}
            finally:
                await signer.close()
        registry = Registry(settings.registry, strict=True, client_id=settings.client_id)
        await registry.start()
        try:
            await registry.health()
            checks["registry"] = {"ok": True}
            for alias, identity in settings.agents.items():
                try:
                    record = await registry.resolve(identity.agent_id)
                except AgentAuthError as exc:
                    if exc.code != "AGENT_NOT_FOUND":
                        raise
                    checks[f"registry:{alias}"] = {"published": False}
                else:
                    checks[f"registry:{alias}"] = {"kid": record.kid, "published": True}
        finally:
            await registry.close()
    _print({"ok": True, "checks": checks})
    return 0


async def _publish(auth: AgentAuth, alias: str) -> dict[str, object]:
    identity = _identity(auth, alias)
    signer = auth._signers[alias]
    payload = {
        "agent_id": identity.agent_id,
        "endpoint": identity.endpoint,
        "capabilities": list(identity.capabilities),
        "kid": signer.kid,
        "public_key": signer.public_key,
    }
    envelope = await sign_envelope(
        sender=identity.agent_id,
        audience=_registry_audience(auth),
        call_type="registry.publish",
        payload=payload,
        signer=signer,
    )
    result = await auth._registry.mutate(envelope)
    return {"agent_id": identity.agent_id, "kid": result["kid"]}


async def _rotate(auth: AgentAuth, alias: str) -> dict[str, object]:
    identity = _identity(auth, alias)
    current = auth._signers[alias]
    if not isinstance(current, VaultSigner) or auth._settings.vault is None:
        raise AgentAuthError("ROTATE_REQUIRES_VAULT", "Key rotation is only available in production Vault mode")
    latest = await current.latest_version()
    configured = identity.key_version or 0
    new_version = latest if latest > configured else await current.rotate()
    new_identity = replace(identity, key_version=new_version)
    new_signer = VaultSigner(agent_id=identity.agent_id, settings=auth._settings.vault, identity=new_identity)
    await new_signer.start()
    try:
        request_id = str(uuid.uuid4())
        proof_payload = {
            "agent_id": identity.agent_id,
            "new_kid": new_signer.kid,
            "new_public_key": new_signer.public_key,
        }
        proof = await sign_envelope(
            sender=identity.agent_id,
            audience=_registry_audience(auth),
            call_type="registry.rotate.proof",
            payload=proof_payload,
            signer=new_signer,
            reply_to=request_id,
        )
        outer = await sign_envelope(
            sender=identity.agent_id,
            audience=_registry_audience(auth),
            call_type="registry.rotate",
            payload={**proof_payload, "proof": proof.as_dict()},
            signer=current,
            request_id=request_id,
        )
        await auth._registry.mutate(outer)
        _update_key_version(auth._settings.path, alias, new_version)
        return {"agent_id": identity.agent_id, "kid": new_signer.kid, "key_version": new_version}
    finally:
        await new_signer.close()


async def _revoke(auth: AgentAuth, alias: str) -> None:
    identity = _identity(auth, alias)
    envelope = await sign_envelope(
        sender=identity.agent_id,
        audience=_registry_audience(auth),
        call_type="registry.revoke",
        payload={"agent_id": identity.agent_id},
        signer=auth._signers[alias],
    )
    await auth._registry.mutate(envelope)


def _identity(auth: AgentAuth, alias: str) -> Any:
    try:
        return auth._settings.agents[alias]
    except KeyError as exc:
        raise AgentAuthError("IDENTITY_NOT_CONFIGURED", f"Unknown identity alias: {alias}") from exc


def _registry_audience(auth: AgentAuth) -> str:
    if not auth._settings.registry:
        raise AgentAuthError("REGISTRY_UNAVAILABLE", "Registry is not configured")
    return auth._settings.registry


def _update_key_version(path: Path, alias: str, version: int) -> None:
    text = path.read_text(encoding="utf-8")
    section = re.compile(rf"(^\[agents\.{re.escape(alias)}\]\s*$)(.*?)(?=^\[|\Z)", re.MULTILINE | re.DOTALL)
    match = section.search(text)
    if not match:
        raise AgentAuthError("CONFIG_UPDATE_FAILED", f"agents.{alias} section was not found")
    body = match.group(2)
    if re.search(r"^key_version\s*=.*$", body, re.MULTILINE):
        body = re.sub(r"^key_version\s*=.*$", f"key_version = {version}", body, flags=re.MULTILINE)
    else:
        body += f"key_version = {version}\n"
    updated = text[: match.start(2)] + body + text[match.end(2) :]
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(updated, encoding="utf-8")
    os.replace(temporary, path)


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
