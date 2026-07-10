"""签名器抽象与 ES256 验签实现。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .http_utils import _to_base64url, from_base64url


class Signer(Protocol):
    async def kid(self) -> str: ...

    async def algorithm(self) -> str: ...

    async def sign(self, data: bytes) -> bytes: ...


class CallableSigner(Signer):
    """自定义远程签名器适配器。"""

    def __init__(
        self,
        *,
        kid_value: str,
        sign_callable: Callable[[bytes], Awaitable[bytes]],
        algorithm_name: str = "ES256",
    ) -> None:
        self._kid_value = kid_value
        self._sign_callable = sign_callable
        self._algorithm_name = algorithm_name

    async def kid(self) -> str:
        return self._kid_value

    async def algorithm(self) -> str:
        return self._algorithm_name

    async def sign(self, data: bytes) -> bytes:
        return await self._sign_callable(data)


def public_key_to_base64url(public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _to_base64url(public_key_der)


def verify_signature(
    *,
    public_key_pem: str | None,
    public_key_base64url: str | None,
    data: bytes,
    signature_base64url: str,
    alg: str = "ES256",
) -> bool:
    if alg != "ES256":
        raise ValueError(f"Unsupported algorithm: {alg}")
    if public_key_pem:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    elif public_key_base64url:
        raw = from_base64url(public_key_base64url)
        public_key = serialization.load_der_public_key(raw)
    else:
        raise ValueError("public key is required")
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("ES256 requires a P-256 EC public key")

    try:
        signature = from_base64url(signature_base64url)
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
