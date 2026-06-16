"""Registry 安全发布协议：请求签名、验签与 developer 凭证辅助。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from uuid import uuid4

from .crypto import Signer, verify_signature
from .http_utils import canonicalize_headers, ensure_bytes, sha256_base64url, to_iso_z, utc_now
from .models import AgentKey


REGISTRY_SIGNATURE_INPUT = (
    "method path body-digest x-agent-id x-agent-kid x-agent-timestamp x-agent-nonce x-registry-client-id host"
)


@dataclass(slots=True)
class RegistrySignatureHeaders:
    headers: dict[str, str]
    canonical: str
    body_digest: str


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def public_key_fingerprint(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()


def build_registry_publish_canonical(
    *,
    method: str,
    path: str,
    body: bytes | str | dict | list | None,
    agent_id: str,
    kid: str,
    timestamp: str,
    nonce: str,
    client_id: str,
    host: str,
) -> tuple[str, str]:
    body_digest = sha256_base64url(ensure_bytes(body))
    canonical = "\n".join(
        [
            method.upper(),
            path,
            body_digest,
            f"x-agent-id:{agent_id}",
            f"x-agent-kid:{kid}",
            f"x-agent-timestamp:{timestamp}",
            f"x-agent-nonce:{nonce}",
            f"x-registry-client-id:{client_id}",
            f"host:{host}",
        ],
    )
    return canonical, body_digest


async def sign_registry_publish_request(
    *,
    path: str,
    host: str,
    body: bytes | str | dict | list | None,
    agent_id: str,
    client_id: str,
    signer: Signer,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> RegistrySignatureHeaders:
    normalized_headers = canonicalize_headers(None)
    kid = await signer.kid()
    algorithm = await signer.algorithm()
    if algorithm not in {"Ed25519", "ES256"}:
        raise ValueError("Only Ed25519 and ES256 are supported in v1")
    request_timestamp = timestamp or to_iso_z(utc_now())
    request_nonce = nonce or str(uuid4())
    canonical, body_digest = build_registry_publish_canonical(
        method="POST",
        path=path,
        body=body,
        agent_id=agent_id,
        kid=kid,
        timestamp=request_timestamp,
        nonce=request_nonce,
        client_id=client_id,
        host=host,
    )
    signature = await signer.sign(canonical.encode("utf-8"))
    normalized_headers.update(
        {
            "x-agent-id": agent_id,
            "x-agent-kid": kid,
            "x-agent-timestamp": request_timestamp,
            "x-agent-nonce": request_nonce,
            "x-agent-signature": __import__("base64").urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            "x-registry-client-id": client_id,
            "host": host,
            "x-agent-signature-input": REGISTRY_SIGNATURE_INPUT,
        },
    )
    return RegistrySignatureHeaders(headers=normalized_headers, canonical=canonical, body_digest=body_digest)


def verify_registry_publish_signature(
    *,
    path: str,
    host: str,
    body: bytes | str | dict | list | None,
    headers: dict[str, str],
    public_key: AgentKey,
) -> bool:
    normalized = canonicalize_headers(headers)
    signature = normalized.get("x-agent-signature")
    agent_id = normalized.get("x-agent-id")
    kid = normalized.get("x-agent-kid")
    timestamp = normalized.get("x-agent-timestamp")
    nonce = normalized.get("x-agent-nonce")
    client_id = normalized.get("x-registry-client-id")
    if not all([signature, agent_id, kid, timestamp, nonce, client_id]):
        return False
    canonical, _ = build_registry_publish_canonical(
        method="POST",
        path=path,
        body=body,
        agent_id=agent_id,
        kid=kid,
        timestamp=timestamp,
        nonce=nonce,
        client_id=client_id,
        host=host,
    )
    return verify_signature(
        public_key_pem=public_key.public_key_pem,
        public_key_base64url=public_key.public_key_base64url,
        data=canonical.encode("utf-8"),
        signature_base64url=signature,
        alg=public_key.alg,
    )
