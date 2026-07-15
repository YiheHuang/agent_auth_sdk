"""HashiCorp Vault Transit signer 与公钥解析。"""

from __future__ import annotations

import asyncio
import base64
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import Signer
from .http_utils import _to_base64url


@dataclass(frozen=True, slots=True)
class VaultKmsConfig:
    vault_addr: str
    transit_mount: str
    key_name: str
    vault_token_file: str | Path | None = None
    vault_token: str | None = field(default=None, repr=False)
    namespace: str | None = None
    verify: bool | str = True
    kid: str | None = None
    key_version: int | None = None
    allow_insecure_raw_token: bool = False

    def __post_init__(self) -> None:
        for field_name in ("vault_addr", "transit_mount", "key_name"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} is required")
        parsed_addr = urlparse(self.vault_addr)
        if parsed_addr.scheme not in {"http", "https"} or not parsed_addr.netloc:
            raise ValueError("vault_addr must be an absolute HTTP(S) URL")
        if parsed_addr.username is not None or parsed_addr.password is not None:
            raise ValueError("vault_addr must not contain userinfo")
        if parsed_addr.scheme != "https" and not self.allow_insecure_raw_token:
            raise ValueError("vault_addr must use HTTPS outside explicit dev/test mode")
        if self.verify is False and not self.allow_insecure_raw_token:
            raise ValueError("Disabling Vault TLS verification is only allowed in explicit dev/test mode.")
        if self.vault_token and not self.allow_insecure_raw_token:
            raise ValueError("Raw vault_token is dev/test-only. Use vault_token_file in production.")
        if not self.vault_token_file and not self.vault_token:
            raise ValueError("vault_token_file is required in production.")
        if self.key_version is not None and self.key_version <= 0:
            raise ValueError("key_version must be positive")


@dataclass(frozen=True, slots=True)
class VaultKmsKeyDescription:
    key_name: str
    key_type: str
    latest_version: int
    public_key_pem: str
    public_key_base64url: str
    hash_algorithm: str = "sha2-256"
    marshaling_algorithm: str = "asn1"


class VaultTransitPublicKeyResolver:
    """从 Vault Transit 读取非对称签名公钥。"""

    def __init__(self, config: VaultKmsConfig, client: Any | None = None) -> None:
        self._config = config
        self._client = client or _build_vault_client(config)

    @property
    def client(self) -> Any:
        return self._client

    def describe(self) -> VaultKmsKeyDescription:
        response = self._client.secrets.transit.read_key(
            name=self._config.key_name,
            mount_point=self._config.transit_mount,
        )
        data = response.get("data", {})
        key_type = data.get("type")
        if key_type != "ecdsa-p256":
            raise ValueError(f"Unsupported Vault Transit key type: {key_type}. Expected ecdsa-p256.")
        latest_version = int(data.get("latest_version") or 1)
        selected_version = self._config.key_version or latest_version
        keys = data.get("keys") or {}
        public_key_pem = _select_public_key(keys, selected_version)
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        _validate_p256_public_key(public_key)
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return VaultKmsKeyDescription(
            key_name=self._config.key_name,
            key_type=key_type,
            latest_version=selected_version,
            public_key_pem=public_key_pem,
            public_key_base64url=_to_base64url(public_key_der),
        )


class VaultTransitSigner(Signer):
    """使用 Vault Transit ecdsa-p256 key 执行 ES256 签名。"""

    def __init__(self, config: VaultKmsConfig, client: Any | None = None) -> None:
        self._config = config
        self._client = client or _build_vault_client(config)
        version_suffix = f":v{config.key_version}" if config.key_version is not None else ""
        self._kid = config.kid or f"vault:{config.transit_mount}/{config.key_name}{version_suffix}"

    @property
    def config(self) -> VaultKmsConfig:
        return self._config

    @property
    def client(self) -> Any:
        return self._client

    async def kid(self) -> str:
        return self._kid

    async def algorithm(self) -> str:
        return "ES256"

    async def sign(self, data: bytes) -> bytes:
        return await asyncio.to_thread(self._sign_sync, data)

    def _sign_sync(self, data: bytes) -> bytes:
        kwargs: dict[str, Any] = {}
        if self._config.key_version is not None:
            kwargs["key_version"] = self._config.key_version
        response = self._client.secrets.transit.sign_data(
            name=self._config.key_name,
            hash_input=_base64(data),
            hash_algorithm="sha2-256",
            marshaling_algorithm="asn1",
            mount_point=self._config.transit_mount,
            **kwargs,
        )
        signature = response.get("data", {}).get("signature")
        if not signature:
            raise ValueError("Vault Transit sign response does not contain a signature.")
        return parse_vault_signature(signature)

    def validate_access(self) -> None:
        kwargs: dict[str, Any] = {}
        if self._config.key_version is not None:
            kwargs["key_version"] = self._config.key_version
        response = self._client.secrets.transit.sign_data(
            name=self._config.key_name,
            hash_input=_base64(b"agent-auth-sdk:vault-transit-probe"),
            hash_algorithm="sha2-256",
            marshaling_algorithm="asn1",
            mount_point=self._config.transit_mount,
            **kwargs,
        )
        if not response.get("data", {}).get("signature"):
            raise ValueError("Vault Transit probe signing returned an empty signature.")


def build_vault_transit_signer(config: VaultKmsConfig) -> VaultTransitSigner:
    return VaultTransitSigner(config)


def resolve_vault_public_key(config: VaultKmsConfig) -> VaultKmsKeyDescription:
    return VaultTransitPublicKeyResolver(config).describe()


def validate_vault_key(config: VaultKmsConfig) -> VaultKmsKeyDescription:
    description = resolve_vault_public_key(config)
    VaultTransitSigner(config).validate_access()
    return description


def parse_vault_signature(signature: str) -> bytes:
    parts = signature.split(":", 2)
    if len(parts) != 3 or parts[0] != "vault":
        raise ValueError("Invalid Vault Transit signature format.")
    return base64.b64decode(parts[2])


def _build_vault_client(config: VaultKmsConfig) -> Any:
    try:
        import hvac
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError("hvac is required for Vault Transit support. Install project dependencies first.") from exc
    return hvac.Client(
        url=config.vault_addr,
        token=read_vault_token(config),
        namespace=config.namespace,
        verify=config.verify,
    )


def _ensure_transit_key(config: VaultKmsConfig, client: Any | None = None) -> bool:
    """确保 Vault Transit key 存在；若不存在，创建 ecdsa-p256 类型密钥。

    Returns:
        True 表示密钥是新创建的，False 表示密钥已存在。
    """
    client = client or _build_vault_client(config)
    try:
        client.secrets.transit.read_key(
            name=config.key_name,
            mount_point=config.transit_mount,
        )
        return False
    except Exception as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if exc.__class__.__name__ != "InvalidPath" and status_code != 404:
            raise
        client.secrets.transit.create_key(
            name=config.key_name,
            key_type="ecdsa-p256",
            mount_point=config.transit_mount,
        )
        return True


def read_vault_token(config: VaultKmsConfig) -> str:
    if config.vault_token_file:
        path = Path(config.vault_token_file)
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Unable to read Vault token file: {path}") from exc
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError(f"Vault token file permissions are too broad: {path}")
        lines = content.splitlines()
        token = lines[0].strip() if lines else ""
        if any(line.strip() for line in lines[1:]):
            raise ValueError(f"Vault token file must contain exactly one token line: {path}")
        if not token:
            raise ValueError(f"Vault token file is empty: {path}")
        return token
    if config.vault_token and config.allow_insecure_raw_token:
        return config.vault_token
    raise ValueError("vault_token_file is required in production.")


def _base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _select_public_key(keys: dict, key_version: int) -> str:
    for version in (str(key_version), key_version):
        value = keys.get(version)
        if isinstance(value, dict) and value.get("public_key"):
            return str(value["public_key"])
    raise ValueError(f"Vault Transit key metadata does not contain public key version {key_version}.")


def _validate_p256_public_key(public_key: Any) -> None:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Vault Transit public key must be an EC public key.")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("Unsupported Vault Transit key type. Expected ecdsa-p256.")
