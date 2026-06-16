"""HashiCorp Vault Transit signer 与公钥解析。"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import Signer
from .http_utils import _to_base64url


@dataclass(frozen=True, slots=True)
class VaultKmsConfig:
    vault_addr: str
    vault_token: str
    transit_mount: str
    key_name: str
    namespace: str | None = None
    verify: bool | str = True
    kid: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("vault_addr", "vault_token", "transit_mount", "key_name"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} is required")


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
        keys = data.get("keys") or {}
        public_key_pem = _select_public_key(keys, latest_version)
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        _validate_p256_public_key(public_key)
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return VaultKmsKeyDescription(
            key_name=self._config.key_name,
            key_type=key_type,
            latest_version=latest_version,
            public_key_pem=public_key_pem,
            public_key_base64url=_to_base64url(public_key_der),
        )


class VaultTransitSigner(Signer):
    """使用 Vault Transit ecdsa-p256 key 执行 ES256 签名。"""

    def __init__(self, config: VaultKmsConfig, client: Any | None = None) -> None:
        self._config = config
        self._client = client or _build_vault_client(config)
        self._kid = config.kid or f"vault:{config.transit_mount}/{config.key_name}"

    async def kid(self) -> str:
        return self._kid

    async def algorithm(self) -> str:
        return "ES256"

    async def sign(self, data: bytes) -> bytes:
        response = self._client.secrets.transit.sign_data(
            name=self._config.key_name,
            hash_input=_base64(data),
            hash_algorithm="sha2-256",
            marshaling_algorithm="asn1",
            mount_point=self._config.transit_mount,
        )
        signature = response.get("data", {}).get("signature")
        if not signature:
            raise ValueError("Vault Transit sign response does not contain a signature.")
        return parse_vault_signature(signature)

    def validate_access(self) -> None:
        response = self._client.secrets.transit.sign_data(
            name=self._config.key_name,
            hash_input=_base64(b"agent-auth-sdk:vault-transit-probe"),
            hash_algorithm="sha2-256",
            marshaling_algorithm="asn1",
            mount_point=self._config.transit_mount,
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
        token=config.vault_token,
        namespace=config.namespace,
        verify=config.verify,
    )


def _base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _select_public_key(keys: dict, latest_version: int) -> str:
    for version in (str(latest_version), latest_version):
        value = keys.get(version)
        if isinstance(value, dict) and value.get("public_key"):
            return value["public_key"]
    raise ValueError("Vault Transit key metadata does not contain a public key for the latest version.")


def _validate_p256_public_key(public_key: Any) -> None:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Vault Transit public key must be an EC public key.")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("Unsupported Vault Transit key type. Expected ecdsa-p256.")
