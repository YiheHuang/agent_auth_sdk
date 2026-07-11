"""示例共享代码。LocalEs256Signer 只能用于本地演示和测试。"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agent_auth_sdk import AgentInstance, AgentRegistryDocument, AgentRegistryEntry


class LocalEs256Signer:
    """进程内临时 ES256 signer；退出后私钥丢失，不得用于生产。"""

    def __init__(self, kid: str) -> None:
        self._kid = kid
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    async def kid(self) -> str:
        return self._kid

    async def algorithm(self) -> str:
        return "ES256"

    async def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def public_key_pem(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )


def local_agent(name: str, *, domain: str = "127.0.0.1:9001") -> AgentInstance:
    signer = LocalEs256Signer(kid=f"local:{name}")
    return AgentInstance.from_signer(
        domain=domain,
        name=name,
        organization="Agent Auth local example",
        endpoint=f"http://{domain}/{name}/invoke",
        signer=signer,
        public_key_pem=signer.public_key_pem(),
        kid=f"local:{name}",
        capabilities=[f"example.{name}"],
        environment="local",
    )


def registry_transport(agents: Iterable[AgentInstance]) -> httpx.MockTransport:
    entries = {
        agent.agent_id: AgentRegistryEntry(
            agent_id=agent.agent_id,
            metadata=agent.metadata,
            published_at=datetime.now(UTC),
            publisher="local-example",
        )
        for agent in agents
        if agent.metadata is not None
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/agents/resolve":
            agent_id = request.url.params.get("agent_id")
            entry = entries.get(agent_id or "")
            if entry is None:
                return httpx.Response(404, json={"detail": "AGENT_NOT_FOUND"})
            return httpx.Response(
                200,
                json={"agent_id": entry.agent_id, "metadata": entry.metadata.model_dump(mode="json")},
            )
        if request.url.path == "/.well-known/agent.json":
            document = AgentRegistryDocument(updated_at=datetime.now(UTC), agents=list(entries.values()))
            return httpx.Response(200, json=document.model_dump(mode="json"))
        return httpx.Response(404, json={"detail": "NOT_FOUND"})

    return httpx.MockTransport(handler)


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def vault_verify_from_env() -> bool | str:
    value = os.getenv("AGENT_AUTH_VAULT_VERIFY", "true").strip()
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    return value
