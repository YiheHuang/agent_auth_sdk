"""通过 httpx 直接访问 Vault Transit。"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Any

import httpx

from ._config import IdentitySettings, VaultSettings
from ._errors import AgentAuthError
from ._protocol import public_key_from_pem


class VaultSigner:
    def __init__(
        self,
        *,
        agent_id: str,
        settings: VaultSettings,
        identity: IdentitySettings,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not identity.key or not identity.key_version:
            raise AgentAuthError("VAULT_CONFIG_INVALID", "Vault key and key_version are required")
        self.agent_id = agent_id
        self.settings = settings
        self.identity = identity
        self.token = read_token(identity)
        self._client = client
        self._owns_client = client is None
        self._public_key: str | None = None

    @property
    def kid(self) -> str:
        return f"{self.agent_id}#key:v{self.identity.key_version}"

    @property
    def public_key(self) -> str:
        if self._public_key is None:
            raise AgentAuthError("VAULT_NOT_READY", "Vault signer has not been initialized")
        return self._public_key

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.settings.url + "/",
                verify=self.settings.verify,
                timeout=10,
                follow_redirects=False,
            )
        data = await self._request("GET", f"v1/{self.settings.mount}/keys/{self.identity.key}")
        keys = data.get("data", {}).get("keys", {})
        selected = keys.get(str(self.identity.key_version)) or keys.get(self.identity.key_version)
        if not isinstance(selected, dict) or not selected.get("public_key"):
            raise AgentAuthError("VAULT_KEY_VERSION_NOT_FOUND", "Configured Vault key version was not found")
        self._public_key = public_key_from_pem(str(selected["public_key"]))

    async def sign(self, data: bytes) -> bytes:
        payload = {
            "input": base64.b64encode(data).decode("ascii"),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "asn1",
            "key_version": self.identity.key_version,
        }
        response = await self._request("POST", f"v1/{self.settings.mount}/sign/{self.identity.key}", json=payload)
        signature = response.get("data", {}).get("signature")
        if not isinstance(signature, str):
            raise AgentAuthError("VAULT_RESPONSE_INVALID", "Vault sign response is invalid")
        parts = signature.split(":", 2)
        expected_version = f"v{self.identity.key_version}"
        if len(parts) != 3 or parts[0] != "vault" or parts[1] != expected_version:
            raise AgentAuthError("VAULT_RESPONSE_INVALID", "Vault signature format is invalid")
        try:
            return base64.b64decode(parts[2], validate=True)
        except ValueError as exc:
            raise AgentAuthError("VAULT_RESPONSE_INVALID", "Vault signature is not valid base64") from exc

    async def latest_version(self) -> int:
        data = await self._request("GET", f"v1/{self.settings.mount}/keys/{self.identity.key}")
        try:
            return int(data["data"]["latest_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentAuthError("VAULT_RESPONSE_INVALID", "Vault key response is invalid") from exc

    async def rotate(self) -> int:
        await self._request("POST", f"v1/{self.settings.mount}/keys/{self.identity.key}/rotate", json={})
        return await self.latest_version()

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
        self._client = None

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if self._client is None:
            raise AgentAuthError("VAULT_NOT_READY", "Vault signer has not been initialized")
        headers = {"X-Vault-Token": self.token}
        if self.settings.namespace:
            headers["X-Vault-Namespace"] = self.settings.namespace
        try:
            response = await self._client.request(method, path, headers=headers, **kwargs)
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            return value
        except httpx.HTTPStatusError as exc:
            raise AgentAuthError(
                "VAULT_REQUEST_FAILED",
                "Vault rejected the request",
                details={"status": exc.response.status_code},
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise AgentAuthError("VAULT_REQUEST_FAILED", "Vault request failed") from exc


def read_token(identity: IdentitySettings) -> str:
    alias = "".join(character if character.isalnum() else "_" for character in identity.alias).upper()
    value = os.getenv(f"AGENT_AUTH_VAULT_TOKEN_{alias}") or os.getenv("AGENT_AUTH_VAULT_TOKEN")
    if value:
        return value
    if identity.token_file is None:
        raise AgentAuthError("VAULT_TOKEN_MISSING", f"No Vault token configured for {identity.alias}")
    path = Path(identity.token_file)
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AgentAuthError("VAULT_TOKEN_UNREADABLE", "Vault token file cannot be read") from exc
    if not token:
        raise AgentAuthError("VAULT_TOKEN_EMPTY", "Vault token file is empty")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AgentAuthError("VAULT_TOKEN_PERMISSIONS", "Vault token file permissions must be 0600 or stricter")
    return token
