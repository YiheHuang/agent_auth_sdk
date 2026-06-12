"""签名器、公私钥生成和验签实现。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .http_utils import _to_base64url, from_base64url
from .models import GeneratedKeyPair


class Signer(Protocol):
    async def kid(self) -> str: ...

    async def algorithm(self) -> str: ...

    async def sign(self, data: bytes) -> bytes: ...


class CallableSigner(Signer):
    """未来接 KMS/HSM 时只需传一个可调用函数即可接入。"""

    def __init__(
        self,
        *,
        kid_value: str,
        sign_callable: Callable[[bytes], Awaitable[bytes]],
        algorithm_name: str = "Ed25519",
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


@dataclass(slots=True)
class LocalPemSigner(Signer):
    """本地 PEM 私钥签名器，用于开发、测试和简单部署。"""

    private_key_pem: str
    kid_value: str

    def __post_init__(self) -> None:
        self._private_key = serialization.load_pem_private_key(
            self.private_key_pem.encode("utf-8"),
            password=None,
        )

    async def kid(self) -> str:
        return self.kid_value

    async def algorithm(self) -> str:
        return "Ed25519"

    async def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


def generate_ed25519_keypair(*, kid: str = "main") -> GeneratedKeyPair:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return GeneratedKeyPair(
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        public_key_base64url=_to_base64url(public_key_der),
        kid=kid,
    )


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
) -> bool:
    if public_key_pem:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    elif public_key_base64url:
        public_key = Ed25519PublicKey.from_public_bytes(
            _extract_raw_public_key(from_base64url(public_key_base64url)),
        )
    else:
        raise ValueError("public key is required")

    try:
        public_key.verify(from_base64url(signature_base64url), data)
        return True
    except Exception:
        return False


def _extract_raw_public_key(der_or_raw: bytes) -> bytes:
    # DER 编码的 SubjectPublicKeyInfo 固定以 12 字节前缀引导到 32 字节原始公钥。
    if len(der_or_raw) == 32:
        return der_or_raw
    return der_or_raw[-32:]

