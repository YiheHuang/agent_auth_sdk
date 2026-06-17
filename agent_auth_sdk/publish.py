"""用于生成、落盘和导出 well-known metadata。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .crypto import Signer
from .models import AgentAuditConfig, AgentKey, AgentMetadata
from .registry_security import sign_registry_add_key_proof, sign_registry_new_key_proof, sign_registry_publish_request


def render_agent_metadata(
    *,
    agent_id: str,
    domain: str,
    name: str,
    organization: str,
    endpoint: str,
    capabilities: list[str],
    keys: list[AgentKey],
    revoked_kids: list[str] | None = None,
    environment: str | None = None,
    signing_policy: dict | None = None,
    verification_policy: dict | None = None,
    audit: AgentAuditConfig | None = None,
) -> AgentMetadata:
    return AgentMetadata(
        version="1.0",
        agent_id=agent_id,
        domain=domain,
        name=name,
        organization=organization,
        endpoint=endpoint,
        capabilities=capabilities,
        keys=keys,
        revoked_kids=revoked_kids or [],
        updated_at=datetime.now(timezone.utc),
        environment=environment,
        signing_policy=signing_policy,
        verification_policy=verification_policy,
        audit=audit,
    )


def export_well_known(metadata: AgentMetadata, output_dir: str | Path) -> Path:
    target_dir = Path(output_dir) / ".well-known"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "agent.json"
    target_file.write_text(
        json.dumps(metadata.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return target_file


async def publish_to_registry(
    metadata: AgentMetadata,
    *,
    registry_url: str,
    client_id: str,
    api_key: str,
    signer: Signer,
    http_client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
) -> dict:
    """将 Agent metadata 发布到中心注册服务器。"""

    payload = {
        "agent_id": metadata.agent_id,
        "metadata": metadata.model_dump(mode="json"),
        "publish_intent": "upsert_metadata",
    }
    parsed = urlparse(registry_url)
    path = parsed.path or "/"
    signed = await sign_registry_publish_request(
        path=path,
        host=parsed.netloc,
        body=payload,
        agent_id=metadata.agent_id,
        client_id=client_id,
        signer=signer,
    )
    headers = dict(signed.headers)
    headers["authorization"] = f"Bearer {api_key}"

    if http_client is not None:
        response = await http_client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()

    async with httpx.AsyncClient() as client:
        response = await client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()


async def rotate_key_in_registry(
    *,
    agent_id: str,
    new_key: AgentKey,
    registry_url: str,
    client_id: str,
    api_key: str,
    current_signer: Signer,
    new_signer: Signer,
    http_client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
) -> dict:
    """显式轮换 registry 中的 Agent active key，并证明新私钥可控。"""

    parsed = urlparse(registry_url)
    path = parsed.path or "/"
    host = parsed.netloc
    proof = await sign_registry_new_key_proof(
        agent_id=agent_id,
        new_key=new_key,
        client_id=client_id,
        host=host,
        signer=new_signer,
    )
    payload = {
        "agent_id": agent_id,
        "new_key": new_key.model_dump(mode="json"),
        "new_key_proof_headers": proof.headers,
    }
    signed = await sign_registry_publish_request(
        path=path,
        host=host,
        body=payload,
        agent_id=agent_id,
        client_id=client_id,
        signer=current_signer,
    )
    headers = dict(signed.headers)
    headers["authorization"] = f"Bearer {api_key}"

    if http_client is not None:
        response = await http_client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()

    async with httpx.AsyncClient() as client:
        response = await client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()


async def add_key_in_registry(
    *,
    agent_id: str,
    new_key: AgentKey,
    registry_url: str,
    client_id: str,
    api_key: str,
    current_signer: Signer,
    new_signer: Signer,
    http_client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
) -> dict:
    """为 Agent 添加额外活跃密钥，保留已有 active key 不变。

    需要双重签名证明：(1) 当前 active key 签名完整请求 (2) 新 key 签名 proof。
    """

    parsed = urlparse(registry_url)
    path = parsed.path or "/"
    host = parsed.netloc
    proof = await sign_registry_add_key_proof(
        agent_id=agent_id,
        new_key=new_key,
        client_id=client_id,
        host=host,
        signer=new_signer,
    )
    payload = {
        "agent_id": agent_id,
        "new_key": new_key.model_dump(mode="json"),
        "new_key_proof_headers": proof.headers,
    }
    signed = await sign_registry_publish_request(
        path=path,
        host=host,
        body=payload,
        agent_id=agent_id,
        client_id=client_id,
        signer=current_signer,
    )
    headers = dict(signed.headers)
    headers["authorization"] = f"Bearer {api_key}"

    if http_client is not None:
        response = await http_client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()

    async with httpx.AsyncClient() as client:
        response = await client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()


async def revoke_key_in_registry(
    *,
    agent_id: str,
    kid_to_revoke: str,
    registry_url: str,
    client_id: str,
    api_key: str,
    current_signer: Signer,
    http_client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
) -> dict:
    """显式撤销 Agent 的某个密钥，将其加入 revoked_kids 黑名单。

    仅需当前 active key 单签名（不涉及新 key 引入，无需双重签名）。
    """

    parsed = urlparse(registry_url)
    path = parsed.path or "/"
    host = parsed.netloc
    payload = {
        "agent_id": agent_id,
        "kid_to_revoke": kid_to_revoke,
    }
    signed = await sign_registry_publish_request(
        path=path,
        host=host,
        body=payload,
        agent_id=agent_id,
        client_id=client_id,
        signer=current_signer,
    )
    headers = dict(signed.headers)
    headers["authorization"] = f"Bearer {api_key}"

    if http_client is not None:
        response = await http_client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()

    async with httpx.AsyncClient() as client:
        response = await client.post(registry_url, json=payload, headers=headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()


async def revoke_agent_in_registry(
    *,
    agent_id: str,
    registry_url: str,
    client_id: str,
    api_key: str,
    current_signer: Signer,
    http_client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
) -> dict:
    """向 Registry 提交 Agent 撤销请求，需 active key 签名。"""

    parsed = urlparse(registry_url)
    path = parsed.path or "/"
    host = parsed.netloc
    payload = {"agent_id": agent_id}
    signed = await sign_registry_publish_request(
        path=path,
        host=host,
        body=payload,
        agent_id=agent_id,
        client_id=client_id,
        signer=current_signer,
    )
    resp_headers = dict(signed.headers)
    resp_headers["authorization"] = f"Bearer {api_key}"

    if http_client is not None:
        response = await http_client.post(registry_url, json=payload, headers=resp_headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()

    async with httpx.AsyncClient() as client:
        response = await client.post(registry_url, json=payload, headers=resp_headers, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()
