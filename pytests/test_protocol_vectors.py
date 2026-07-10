from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from agent_auth_sdk.crypto import verify_signature
from agent_auth_sdk.http_utils import build_canonical_request, canonical_json_bytes, from_base64url
from agent_auth_sdk.messaging import build_canonical_message
from agent_auth_sdk.models import AgentKey
from agent_auth_sdk.registry_security import agent_key_fingerprint


def test_protocol_v1_golden_vectors() -> None:
    vector = json.loads((Path(__file__).parents[1] / "docs" / "protocol-v1-vectors.json").read_text(encoding="utf-8"))
    payload = vector["json_payload"]
    assert canonical_json_bytes(payload).hex() == vector["canonical_json_utf8_hex"]

    http = vector["http"]
    canonical, digest = build_canonical_request(
        method=http["method"],
        url=http["url"],
        body=payload,
        agent_id=http["agent_id"],
        kid=http["kid"],
        timestamp=http["timestamp"],
        nonce=http["nonce"],
    )
    assert canonical == http["canonical"]
    assert digest == vector["payload_sha256_base64url"]

    crypto = vector["crypto"]
    public_key = AgentKey(
        kid=http["kid"],
        public_key_base64url=crypto["public_key_spki_der_base64url"],
    )
    assert agent_key_fingerprint(public_key) == crypto["public_key_fingerprint_sha256_hex"]
    signature = from_base64url(crypto["http_canonical_signature_der_base64url"])
    r, s = decode_dss_signature(signature)
    assert r > 0 and s > 0
    assert verify_signature(
        public_key_pem=None,
        public_key_base64url=crypto["public_key_spki_der_base64url"],
        data=canonical.encode("utf-8"),
        signature_base64url=crypto["http_canonical_signature_der_base64url"],
        alg="ES256",
    )

    message = vector["message"]
    canonical, digest = build_canonical_message(
        agent_id=http["agent_id"],
        kid=http["kid"],
        timestamp=http["timestamp"],
        nonce=http["nonce"],
        payload=payload,
        payload_type=message["payload_type"],
        recipient=message["recipient"],
        message_type=message["message_type"],
    )
    assert canonical == message["canonical"]
    assert digest == vector["payload_sha256_base64url"]
