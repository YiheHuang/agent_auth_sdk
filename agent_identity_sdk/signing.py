"""请求签名逻辑。"""

from __future__ import annotations

import asyncio
from uuid import uuid4

from .config import SigningConfig
from .crypto import Signer
from .http_utils import _to_base64url, build_canonical_request, canonicalize_headers, to_iso_z, utc_now
from .identity import parse_agent_id
from .models import SignatureHeaders


SIGNATURE_INPUT = (
    "method path body-digest x-agent-id x-agent-kid x-agent-timestamp x-agent-nonce host"
)


async def sign_http_request(
    *,
    method: str,
    url: str,
    body: bytes | str | dict | list | None,
    agent_id: str,
    signer: Signer,
    headers: dict[str, str] | None = None,
    config: SigningConfig | None = None,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> SignatureHeaders:
    parse_agent_id(agent_id)
    config = config or SigningConfig()
    normalized_headers = canonicalize_headers(headers)

    kid = await signer.kid()
    if await signer.algorithm() != "Ed25519":
        raise ValueError("Only Ed25519 is supported in v1")

    request_timestamp = timestamp or to_iso_z(utc_now())
    request_nonce = nonce or str(uuid4())
    canonical, body_digest = build_canonical_request(
        method=method,
        url=url,
        body=body,
        agent_id=agent_id,
        kid=kid,
        timestamp=request_timestamp,
        nonce=request_nonce,
        host=normalized_headers.get("host"),
    )
    signature = await signer.sign(canonical.encode("utf-8"))
    normalized_headers.update(
        {
            "x-agent-id": agent_id,
            "x-agent-kid": kid,
            "x-agent-timestamp": request_timestamp,
            "x-agent-nonce": request_nonce,
            "x-agent-signature": _to_base64url(signature),
            "host": normalized_headers.get("host") or __import__("urllib.parse").parse.urlparse(url).netloc,
        },
    )
    if config.include_signature_input_header:
        normalized_headers["x-agent-signature-input"] = SIGNATURE_INPUT
    return SignatureHeaders(headers=normalized_headers, canonical=canonical, body_digest=body_digest)


def sign_http_request_sync(**kwargs: object) -> SignatureHeaders:
    return asyncio.run(sign_http_request(**kwargs))

