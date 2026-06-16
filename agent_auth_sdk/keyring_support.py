"""加密私钥容器、口令解析与本地安全 signer。"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import LocalPemSigner, Signer, generate_ed25519_keypair, public_key_to_base64url
from .http_utils import _to_base64url, from_base64url


DEFAULT_PASSPHRASE_ENV = "AGENT_AUTH_KEY_PASSPHRASE"


class PassphraseResolutionError(ValueError):
    """无法解析密钥解锁口令。"""


@dataclass(slots=True)
class PassphraseSecretProvider:
    """按固定优先级解析本地密钥解锁口令。"""

    env_var: str = DEFAULT_PASSPHRASE_ENV
    allow_keyring: bool = True
    keyring_service: str = "agent_auth_sdk"
    keyring_username: str = "default"

    def resolve(self, passphrase: str | None = None) -> str:
        if passphrase:
            return passphrase

        env_value = os.getenv(self.env_var)
        if env_value:
            return env_value

        if self.allow_keyring:
            try:
                import keyring  # type: ignore
            except ModuleNotFoundError:
                keyring = None
            if keyring is not None:
                secret = keyring.get_password(self.keyring_service, self.keyring_username)
                if secret:
                    return secret

        raise PassphraseResolutionError(
            f"Passphrase is required. Provide it explicitly, set {self.env_var}, or configure OS keyring.",
        )


@dataclass(slots=True)
class EncryptedKeyFile:
    """以 JSON envelope 持久化加密后的 Ed25519 私钥。"""

    version: str
    kid: str
    alg: str
    public_key_pem: str
    public_key_base64url: str
    kdf: str
    kdf_params: dict[str, int]
    cipher: str
    nonce: str
    ciphertext: str

    @classmethod
    def create(
        cls,
        *,
        output_path: str | Path,
        kid: str = "main",
        passphrase: str,
    ) -> tuple["EncryptedKeyFile", dict[str, str]]:
        pair = generate_ed25519_keypair(kid=kid)
        document = cls.encrypt_private_key(
            private_key_pem=pair.private_key_pem,
            public_key_pem=pair.public_key_pem,
            kid=kid,
            passphrase=passphrase,
        )
        document.write(output_path)
        return document, {
            "private_key_pem": pair.private_key_pem,
            "public_key_pem": pair.public_key_pem,
            "public_key_base64url": pair.public_key_base64url,
            "kid": pair.kid,
        }

    @classmethod
    def encrypt_private_key(
        cls,
        *,
        private_key_pem: str,
        public_key_pem: str,
        kid: str,
        passphrase: str,
    ) -> "EncryptedKeyFile":
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(
            passphrase=passphrase,
            salt=salt,
            n=2**14,
            r=8,
            p=1,
        )
        ciphertext = AESGCM(key).encrypt(nonce, private_key_pem.encode("utf-8"), None)
        return cls(
            version="1.0",
            kid=kid,
            alg="Ed25519",
            public_key_pem=public_key_pem,
            public_key_base64url=public_key_to_base64url(public_key_pem),
            kdf="scrypt",
            kdf_params={"salt": _to_base64url(salt), "n": 2**14, "r": 8, "p": 1},
            cipher="aes-256-gcm",
            nonce=_to_base64url(nonce),
            ciphertext=_to_base64url(ciphertext),
        )

    @classmethod
    def load(cls, path: str | Path) -> "EncryptedKeyFile":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**payload)

    def write(self, output_path: str | Path) -> Path:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return target

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "kid": self.kid,
            "alg": self.alg,
            "public_key_pem": self.public_key_pem,
            "public_key_base64url": self.public_key_base64url,
            "kdf": self.kdf,
            "kdf_params": self.kdf_params,
            "cipher": self.cipher,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }

    def decrypt_private_key_pem(self, *, passphrase: str) -> str:
        if self.kdf != "scrypt":
            raise ValueError(f"Unsupported kdf: {self.kdf}")
        if self.cipher != "aes-256-gcm":
            raise ValueError(f"Unsupported cipher: {self.cipher}")
        key = _derive_key(
            passphrase=passphrase,
            salt=from_base64url(self.kdf_params["salt"]),
            n=int(self.kdf_params["n"]),
            r=int(self.kdf_params["r"]),
            p=int(self.kdf_params["p"]),
        )
        plaintext = AESGCM(key).decrypt(
            from_base64url(self.nonce),
            from_base64url(self.ciphertext),
            None,
        )
        return plaintext.decode("utf-8")


@dataclass(slots=True)
class EncryptedFileSigner(Signer):
    """基于加密私钥文件的 signer。"""

    key_path: str | Path
    kid_value: str | None = None
    passphrase: str | None = None
    secret_provider: PassphraseSecretProvider | None = None

    def __post_init__(self) -> None:
        provider = self.secret_provider or PassphraseSecretProvider()
        self._provider = provider
        self._key_document = EncryptedKeyFile.load(self.key_path)
        resolved_passphrase = provider.resolve(self.passphrase)
        private_key_pem = self._key_document.decrypt_private_key_pem(passphrase=resolved_passphrase)
        self._delegate = LocalPemSigner(
            private_key_pem=private_key_pem,
            kid_value=self.kid_value or self._key_document.kid,
        )

    @property
    def public_key_pem(self) -> str:
        return self._key_document.public_key_pem

    @property
    def public_key_base64url(self) -> str:
        return self._key_document.public_key_base64url

    @property
    def resolved_kid(self) -> str:
        return self.kid_value or self._key_document.kid

    async def kid(self) -> str:
        return await self._delegate.kid()

    async def algorithm(self) -> str:
        return await self._delegate.algorithm()

    async def sign(self, data: bytes) -> bytes:
        return await self._delegate.sign(data)


def _derive_key(*, passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=n,
        r=r,
        p=p,
    )
    return kdf.derive(passphrase.encode("utf-8"))
