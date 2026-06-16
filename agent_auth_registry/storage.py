"""Registry 的 SQLite 权威存储。"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_auth_sdk.models import AgentMetadata, AgentRegistryDocument, AgentRegistryEntry


@dataclass(slots=True)
class DeveloperRecord:
    developer_id: str
    client_id: str
    api_key_hash: str
    status: str
    created_at: str
    revoked_at: str | None


@dataclass(slots=True)
class OwnershipRecord:
    agent_id: str
    owner_developer_id: str
    current_kid: str
    public_key_fingerprint: str
    status: str
    created_at: str
    updated_at: str


@dataclass(slots=True)
class RegistryEntryRecord:
    agent_id: str
    metadata_json: str
    owner_developer_id: str
    current_kid: str
    public_key_fingerprint: str
    published_at: str
    updated_at: str
    last_verified_publish_at: str


class RegistryStore:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS developers (
                    developer_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL UNIQUE,
                    api_key_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS agent_ownership (
                    agent_id TEXT PRIMARY KEY,
                    owner_developer_id TEXT NOT NULL,
                    current_kid TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_registry_entries (
                    agent_id TEXT PRIMARY KEY,
                    metadata_json TEXT NOT NULL,
                    owner_developer_id TEXT NOT NULL,
                    current_kid TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_verified_publish_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS publish_nonces (
                    nonce_key TEXT PRIMARY KEY,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    developer_id TEXT,
                    agent_id TEXT,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    reason_code TEXT,
                    source_ip TEXT,
                    created_at TEXT NOT NULL
                );
                """,
            )

    def create_developer(self, *, developer_id: str, client_id: str, api_key_hash: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO developers(developer_id, client_id, api_key_hash, status, created_at, revoked_at)
                VALUES (?, ?, ?, 'active', ?, NULL)
                """,
                (developer_id, client_id, api_key_hash, now),
            )

    def list_developers(self) -> list[DeveloperRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT developer_id, client_id, api_key_hash, status, created_at, revoked_at FROM developers ORDER BY created_at ASC",
            ).fetchall()
        return [DeveloperRecord(**dict(row)) for row in rows]

    def revoke_developer(self, *, client_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE developers SET status = 'revoked', revoked_at = ? WHERE client_id = ?",
                (_now_iso(), client_id),
            )

    def get_developer_by_client_id(self, client_id: str) -> DeveloperRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT developer_id, client_id, api_key_hash, status, created_at, revoked_at
                FROM developers
                WHERE client_id = ?
                """,
                (client_id,),
            ).fetchone()
        return DeveloperRecord(**dict(row)) if row else None

    def get_ownership(self, agent_id: str) -> OwnershipRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT agent_id, owner_developer_id, current_kid, public_key_fingerprint, status, created_at, updated_at
                FROM agent_ownership
                WHERE agent_id = ?
                """,
                (agent_id,),
            ).fetchone()
        return OwnershipRecord(**dict(row)) if row else None

    def get_registry_entry(self, agent_id: str) -> RegistryEntryRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT agent_id, metadata_json, owner_developer_id, current_kid, public_key_fingerprint, published_at, updated_at, last_verified_publish_at
                FROM agent_registry_entries
                WHERE agent_id = ?
                """,
                (agent_id,),
            ).fetchone()
        return RegistryEntryRecord(**dict(row)) if row else None

    def upsert_agent(
        self,
        *,
        metadata: AgentMetadata,
        developer_id: str,
        current_kid: str,
        public_key_fingerprint: str,
        created_at: str | None = None,
    ) -> None:
        now = _now_iso()
        created = created_at or now
        metadata_json = metadata.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agent_ownership(agent_id, owner_developer_id, current_kid, public_key_fingerprint, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    owner_developer_id = excluded.owner_developer_id,
                    current_kid = excluded.current_kid,
                    public_key_fingerprint = excluded.public_key_fingerprint,
                    status = 'active',
                    updated_at = excluded.updated_at
                """,
                (metadata.agent_id, developer_id, current_kid, public_key_fingerprint, created, now),
            )
            conn.execute(
                """
                INSERT INTO agent_registry_entries(agent_id, metadata_json, owner_developer_id, current_kid, public_key_fingerprint, published_at, updated_at, last_verified_publish_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    owner_developer_id = excluded.owner_developer_id,
                    current_kid = excluded.current_kid,
                    public_key_fingerprint = excluded.public_key_fingerprint,
                    updated_at = excluded.updated_at,
                    last_verified_publish_at = excluded.last_verified_publish_at
                """,
                (metadata.agent_id, metadata_json, developer_id, current_kid, public_key_fingerprint, created, now, now),
            )

    def set_nonce(self, nonce_key: str, expires_at: datetime) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO publish_nonces(nonce_key, expires_at)
                VALUES (?, ?)
                ON CONFLICT(nonce_key) DO UPDATE SET expires_at = excluded.expires_at
                """,
                (nonce_key, expires_at.isoformat()),
            )

    def has_nonce(self, nonce_key: str) -> bool:
        self.sweep_nonces()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT nonce_key FROM publish_nonces WHERE nonce_key = ?",
                (nonce_key,),
            ).fetchone()
        return row is not None

    def sweep_nonces(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM publish_nonces WHERE expires_at <= ?",
                (_now_iso(),),
            )

    def write_audit(
        self,
        *,
        developer_id: str | None,
        agent_id: str | None,
        action: str,
        result: str,
        reason_code: str | None,
        source_ip: str | None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log(developer_id, agent_id, action, result, reason_code, source_ip, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (developer_id, agent_id, action, result, reason_code, source_ip, _now_iso()),
            )

    def render_public_document(self) -> AgentRegistryDocument:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT agent_id, metadata_json, published_at
                FROM agent_registry_entries
                ORDER BY agent_id ASC
                """,
            ).fetchall()
        agents = [
            AgentRegistryEntry(
                agent_id=row["agent_id"],
                metadata=AgentMetadata.model_validate(json.loads(row["metadata_json"])),
                published_at=datetime.fromisoformat(row["published_at"]),
                publisher=None,
            )
            for row in rows
        ]
        return AgentRegistryDocument(updated_at=datetime.now(timezone.utc), agents=agents)

    def write_public_document(self, output_path: str | Path) -> Path:
        document = self.render_public_document()
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document.model_dump_json(indent=2), encoding="utf-8")
        return target


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
