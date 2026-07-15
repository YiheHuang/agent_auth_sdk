"""Vault + Registry 密钥生命周期命令示例。先阅读 examples/README.md。"""

from __future__ import annotations

import argparse
import asyncio
import os

from agent_auth_sdk import AgentInstance, RegistryClient

try:
    from ._shared import required_env, vault_verify_from_env
except ImportError:  # 允许 python examples/key_lifecycle.py
    from _shared import required_env, vault_verify_from_env


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Operate one Agent's Vault-backed Registry keys")
    root.add_argument("--agent-name", default=os.getenv("AGENT_AUTH_AGENT_NAME", "quickstart/sender"))
    root.add_argument("--current-key-name", default=os.getenv("AGENT_AUTH_CURRENT_KEY_NAME"))
    commands = root.add_subparsers(dest="operation", required=True)

    add = commands.add_parser("add", help="Add another active key without changing the current signer")
    add.add_argument("--new-key-name", required=True)

    rotate = commands.add_parser("rotate", help="Replace the designated current signing key")
    rotate.add_argument("--new-key-name", required=True)

    revoke = commands.add_parser("revoke", help="Irreversibly revoke a non-current kid")
    revoke.add_argument("--kid", required=True)
    revoke.add_argument("--yes", action="store_true", help="Confirm the irreversible revocation")
    return root


async def load_agent(agent_name: str, current_key_name: str | None) -> AgentInstance:
    if not current_key_name:
        raise RuntimeError("Set AGENT_AUTH_CURRENT_KEY_NAME or pass --current-key-name")
    domain = required_env("AGENT_AUTH_AGENT_DOMAIN")
    return await asyncio.to_thread(
        AgentInstance.from_vault,
        domain=domain,
        name=agent_name,
        organization="Agent Auth key lifecycle example",
        endpoint=f"https://{domain}/{agent_name}/invoke",
        vault_addr=required_env("AGENT_AUTH_VAULT_ADDR"),
        vault_token_file=required_env("AGENT_AUTH_VAULT_TOKEN_FILE"),
        transit_mount=os.getenv("AGENT_AUTH_VAULT_TRANSIT_MOUNT", "transit"),
        key_name=current_key_name,
        namespace=os.getenv("AGENT_AUTH_VAULT_NAMESPACE") or None,
        verify=vault_verify_from_env(),
        environment="production",
    )


async def run(args: argparse.Namespace) -> None:
    agent = await load_agent(args.agent_name, args.current_key_name)
    registry_url = required_env("AGENT_AUTH_REGISTRY_URL")
    client_id = required_env("AGENT_AUTH_REGISTRY_CLIENT_ID")
    api_key = required_env("AGENT_AUTH_REGISTRY_API_KEY")

    print(f"agent: {agent.agent_id}")
    print(f"current kid: {agent.kid}")
    if args.operation == "add":
        print(f"adding Vault key: {args.new_key_name}")
        result = await agent.add_key(
            registry_url=f"{registry_url.rstrip('/')}/v1/agents/add-key",
            client_id=client_id,
            api_key=api_key,
            new_key_name=args.new_key_name,
        )
    elif args.operation == "rotate":
        print(f"rotating to Vault key: {args.new_key_name}")
        result = await agent.rotate_key(
            registry_url=f"{registry_url.rstrip('/')}/v1/agents/rotate-key",
            client_id=client_id,
            api_key=api_key,
            new_key_name=args.new_key_name,
        )
    else:
        if not args.yes:
            raise RuntimeError("revoke is irreversible; repeat the command with --yes")
        if args.kid == agent.kid:
            raise RuntimeError("refusing to revoke the current signing kid; rotate first")
        print(f"revoking kid: {args.kid}")
        async with RegistryClient(base_url=registry_url, client_id=client_id, api_key=api_key) as registry:
            result = await registry.revoke_key(
                agent_id=agent.agent_id,
                kid_to_revoke=args.kid,
                current_signer=agent.signer,
            )
    print(f"registry result: {result}")


def main() -> None:
    asyncio.run(run(parser().parse_args()))


if __name__ == "__main__":
    main()
