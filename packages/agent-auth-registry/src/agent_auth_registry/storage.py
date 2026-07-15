"""Registry 的 SQLite 权威存储。"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_auth_sdk.identity import normalize_agent_host, normalize_agent_path_prefix
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


@dataclass(slots=True)
class DeveloperNamespaceRecord:
    namespace_id: str
    developer_id: str
    domain: str
    path_prefix: str
    status: str
    created_at: str
    revoked_at: str | None


class AgentStateConflictError(RuntimeError):
    """操作基于过期的 Agent 状态，调用方必须重新解析后重试。"""


class UnsupportedSchemaVersionError(RuntimeError):
    """数据库 schema 版本不属于当前 Registry。"""


SCHEMA_VERSION = 1


class RegistryStore:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._db_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            version_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
            ).fetchone()
            if version_table is not None:
                row = conn.execute("SELECT MAX(version) AS version FROM schema_version").fetchone()
                existing_version = int(row["version"]) if row and row["version"] is not None else 0
                if existing_version not in {0, SCHEMA_VERSION}:
                    raise UnsupportedSchemaVersionError(
                        f"Unsupported Registry schema version {existing_version}; expected {SCHEMA_VERSION}"
                    )
            conn.execute("PRAGMA journal_mode = WAL")
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
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(owner_developer_id) REFERENCES developers(developer_id)
                );

                CREATE TABLE IF NOT EXISTS agent_registry_entries (
                    agent_id TEXT PRIMARY KEY,
                    metadata_json TEXT NOT NULL,
                    owner_developer_id TEXT NOT NULL,
                    current_kid TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_verified_publish_at TEXT NOT NULL,
                    FOREIGN KEY(agent_id) REFERENCES agent_ownership(agent_id),
                    FOREIGN KEY(owner_developer_id) REFERENCES developers(developer_id)
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

                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                INSERT OR IGNORE INTO schema_version(version, applied_at)
                VALUES (1, CURRENT_TIMESTAMP);

                CREATE TABLE IF NOT EXISTS developer_namespaces (
                    namespace_id TEXT PRIMARY KEY,
                    developer_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    path_prefix TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(developer_id) REFERENCES developers(developer_id)
                );

                CREATE INDEX IF NOT EXISTS idx_developer_namespaces_domain
                ON developer_namespaces(domain, status);
                """,
            )

    @property
    def db_path(self) -> Path:
        return self._db_path

    def schema_status(self) -> dict[str, int | bool | str]:
        """返回可安全输出的数据库版本和完整性状态。"""

        with self._connect() as conn:
            row = conn.execute("SELECT MAX(version) AS version FROM schema_version").fetchone()
            version = int(row["version"]) if row and row["version"] is not None else 0
            integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
        return {
            "ok": version == SCHEMA_VERSION and integrity == "ok",
            "schema_version": version,
            "expected_schema_version": SCHEMA_VERSION,
            "integrity": integrity,
        }

    def backup(self, destination: str | Path) -> Path:
        """使用 SQLite online backup API 创建一致性备份。"""

        target = Path(destination)
        if target.resolve() == self._db_path.resolve():
            raise ValueError("backup destination must differ from the Registry database")
        target.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(self._db_path, timeout=5.0)
        destination_conn = sqlite3.connect(target, timeout=5.0)
        try:
            source.execute("PRAGMA busy_timeout = 5000")
            source.backup(destination_conn)
        finally:
            destination_conn.close()
            source.close()
        return target

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
                """
                SELECT developer_id, client_id, api_key_hash, status, created_at, revoked_at
                FROM developers ORDER BY created_at ASC
                """,
            ).fetchall()
        return [DeveloperRecord(**dict(row)) for row in rows]

    def revoke_developer(self, *, client_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE developers SET status = 'revoked', revoked_at = ? WHERE client_id = ?",
                (_now_iso(), client_id),
            )

    def admin_revoke_agent(self, *, agent_id: str) -> bool:
        """管理员在单个事务中撤销 Agent 并记录审计。"""
        now = _now_iso()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE agent_ownership SET status = 'revoked', updated_at = ?
                WHERE agent_id = ? AND status = 'active'
                """,
                (now, agent_id),
            )
            result = "success" if cursor.rowcount == 1 else "rejected"
            reason = None if cursor.rowcount == 1 else "AGENT_NOT_FOUND_OR_INACTIVE"
            conn.execute(
                """
                INSERT INTO audit_log(developer_id, agent_id, action, result, reason_code, source_ip, created_at)
                VALUES (NULL, ?, 'admin_revoke_agent', ?, ?, NULL, ?)
                """,
                (agent_id, result, reason, now),
            )
        return cursor.rowcount == 1

    def update_developer_api_key_hash(self, *, client_id: str, api_key_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE developers SET api_key_hash = ? WHERE client_id = ?",
                (api_key_hash, client_id),
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

    def create_namespace(self, *, developer_id: str, domain: str, path_prefix: str) -> DeveloperNamespaceRecord:
        """创建不与其他 active developer 重叠的精确 domain/path namespace。"""

        domain = normalize_agent_host(domain)
        path_prefix = normalize_agent_path_prefix(path_prefix)
        namespace_id = str(uuid.uuid4())
        now = _now_iso()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            developer = conn.execute(
                "SELECT developer_id FROM developers WHERE developer_id = ? AND status = 'active'",
                (developer_id,),
            ).fetchone()
            if developer is None:
                raise ValueError("active developer not found")
            rows = conn.execute(
                """
                SELECT namespace_id, developer_id, domain, path_prefix, status, created_at, revoked_at
                FROM developer_namespaces
                WHERE domain = ? AND status = 'active'
                """,
                (domain,),
            ).fetchall()
            for row in rows:
                record = DeveloperNamespaceRecord(**dict(row))
                overlaps = (
                    path_prefix == "/"
                    or record.path_prefix == "/"
                    or path_prefix == record.path_prefix
                    or path_prefix.startswith(record.path_prefix + "/")
                    or record.path_prefix.startswith(path_prefix + "/")
                )
                if overlaps:
                    raise ValueError(f"namespace overlaps active assignment owned by developer {record.developer_id}")
            conn.execute(
                """
                INSERT INTO developer_namespaces(
                    namespace_id, developer_id, domain, path_prefix, status, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, 'active', ?, NULL)
                """,
                (namespace_id, developer_id, domain, path_prefix, now),
            )
        return DeveloperNamespaceRecord(namespace_id, developer_id, domain, path_prefix, "active", now, None)

    def list_namespaces(
        self,
        *,
        developer_id: str | None = None,
        domain: str | None = None,
        active_only: bool = False,
    ) -> list[DeveloperNamespaceRecord]:
        clauses: list[str] = []
        values: list[str] = []
        if developer_id is not None:
            clauses.append("developer_id = ?")
            values.append(developer_id)
        if domain is not None:
            clauses.append("domain = ?")
            values.append(domain)
        if active_only:
            clauses.append("status = 'active'")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT namespace_id, developer_id, domain, path_prefix, status, created_at, revoked_at
                FROM developer_namespaces
                """
                + where
                + " ORDER BY domain, path_prefix",
                values,
            ).fetchall()
        return [DeveloperNamespaceRecord(**dict(row)) for row in rows]

    def revoke_namespace(self, *, namespace_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE developer_namespaces
                SET status = 'revoked', revoked_at = ?
                WHERE namespace_id = ? AND status = 'active'
                """,
                (_now_iso(), namespace_id),
            )
        return cursor.rowcount == 1

    def developer_has_namespace(self, *, developer_id: str, domain: str, agent_path: str) -> bool:
        for record in self.list_namespaces(developer_id=developer_id, domain=domain, active_only=True):
            if (
                record.path_prefix == "/"
                or agent_path == record.path_prefix
                or agent_path.startswith(record.path_prefix + "/")
            ):
                return True
        return False

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
                SELECT agent_id, metadata_json, owner_developer_id, current_kid,
                    public_key_fingerprint, published_at, updated_at, last_verified_publish_at
                FROM agent_registry_entries
                WHERE agent_id = ?
                """,
                (agent_id,),
            ).fetchone()
        return RegistryEntryRecord(**dict(row)) if row else None

    def commit_agent_operation(
        self,
        *,
        metadata: AgentMetadata,
        developer_id: str,
        current_kid: str,
        public_key_fingerprint: str,
        nonce_keys: list[str],
        nonce_expires_at: datetime,
        action: str,
        source_ip: str | None,
        create: bool,
        created_at: str | None = None,
        expected_updated_at: str | None = None,
    ) -> bool:
        """原子提交 nonce、Agent 状态和成功审计。"""

        now = _next_updated_at(expected_updated_at)
        created = created_at or now
        metadata_json = metadata.model_dump_json()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM publish_nonces WHERE expires_at <= ?", (now,))
            try:
                for nonce_key in nonce_keys:
                    conn.execute(
                        "INSERT INTO publish_nonces(nonce_key, expires_at) VALUES (?, ?)",
                        (nonce_key, nonce_expires_at.isoformat()),
                    )
            except sqlite3.IntegrityError:
                conn.rollback()
                return False

            if create:
                conn.execute(
                    """
                    INSERT INTO agent_ownership(
                        agent_id, owner_developer_id, current_kid, public_key_fingerprint,
                        status, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (metadata.agent_id, developer_id, current_kid, public_key_fingerprint, created, now),
                )
                conn.execute(
                    """
                    INSERT INTO agent_registry_entries(
                        agent_id, metadata_json, owner_developer_id, current_kid,
                        public_key_fingerprint, published_at, updated_at,
                        last_verified_publish_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.agent_id,
                        metadata_json,
                        developer_id,
                        current_kid,
                        public_key_fingerprint,
                        created,
                        now,
                        now,
                    ),
                )
            else:
                if expected_updated_at is None:
                    raise ValueError("expected_updated_at is required for an Agent update")
                ownership_cursor = conn.execute(
                    """
                    UPDATE agent_ownership
                    SET current_kid = ?, public_key_fingerprint = ?, updated_at = ?
                    WHERE agent_id = ? AND owner_developer_id = ?
                        AND status = 'active' AND updated_at = ?
                    """,
                    (
                        current_kid,
                        public_key_fingerprint,
                        now,
                        metadata.agent_id,
                        developer_id,
                        expected_updated_at,
                    ),
                )
                entry_cursor = conn.execute(
                    """
                    UPDATE agent_registry_entries
                    SET metadata_json = ?, current_kid = ?, public_key_fingerprint = ?,
                        updated_at = ?, last_verified_publish_at = ?
                    WHERE agent_id = ? AND owner_developer_id = ? AND updated_at = ?
                    """,
                    (
                        metadata_json,
                        current_kid,
                        public_key_fingerprint,
                        now,
                        now,
                        metadata.agent_id,
                        developer_id,
                        expected_updated_at,
                    ),
                )
                if ownership_cursor.rowcount != 1 or entry_cursor.rowcount != 1:
                    raise AgentStateConflictError("Agent state changed while the operation was in progress")

            conn.execute(
                """
                INSERT INTO audit_log(developer_id, agent_id, action, result, reason_code, source_ip, created_at)
                VALUES (?, ?, ?, 'success', NULL, ?, ?)
                """,
                (developer_id, metadata.agent_id, action, source_ip, now),
            )
        return True

    def commit_revoke_agent(
        self,
        *,
        agent_id: str,
        developer_id: str,
        nonce_key: str,
        nonce_expires_at: datetime,
        source_ip: str | None,
        expected_current_kid: str,
        expected_updated_at: str,
    ) -> bool:
        """原子消费 nonce、撤销 Agent 并写入成功审计。"""

        now = _next_updated_at(expected_updated_at)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM publish_nonces WHERE expires_at <= ?", (now,))
            try:
                conn.execute(
                    "INSERT INTO publish_nonces(nonce_key, expires_at) VALUES (?, ?)",
                    (nonce_key, nonce_expires_at.isoformat()),
                )
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            cursor = conn.execute(
                """
                UPDATE agent_ownership SET status = 'revoked', updated_at = ?
                WHERE agent_id = ? AND owner_developer_id = ? AND status = 'active'
                    AND current_kid = ? AND updated_at = ?
                """,
                (now, agent_id, developer_id, expected_current_kid, expected_updated_at),
            )
            if cursor.rowcount != 1:
                raise AgentStateConflictError("Agent state changed while the operation was in progress")
            conn.execute(
                """
                INSERT INTO audit_log(developer_id, agent_id, action, result, reason_code, source_ip, created_at)
                VALUES (?, ?, 'revoke_agent', 'success', NULL, ?, ?)
                """,
                (developer_id, agent_id, source_ip, now),
            )
        return True

    def has_nonce(self, nonce_key: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT nonce_key FROM publish_nonces WHERE nonce_key = ? AND expires_at > ?",
                (nonce_key, _now_iso()),
            ).fetchone()
        return row is not None

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
                SELECT e.agent_id, e.metadata_json, e.published_at
                FROM agent_registry_entries e
                JOIN agent_ownership o ON e.agent_id = o.agent_id
                WHERE o.status = 'active'
                ORDER BY e.agent_id ASC
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
        updated_at = max(
            (entry.metadata.updated_at for entry in agents),
            default=datetime(1970, 1, 1, tzinfo=UTC),
        )
        return AgentRegistryDocument(updated_at=updated_at, agents=agents)

    def readiness_check(self) -> bool:
        try:
            with self._connect() as conn:
                conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("ROLLBACK")
            return True
        except sqlite3.Error:
            return False

    def write_public_document(self, output_path: str | Path) -> Path:
        document = self.render_public_document()
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document.model_dump_json(indent=2), encoding="utf-8")
        return target


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _next_updated_at(expected_updated_at: str | None) -> str:
    now = datetime.now(UTC)
    if expected_updated_at is None:
        return now.isoformat()
    expected = datetime.fromisoformat(expected_updated_at)
    if now <= expected:
        now = expected + timedelta(microseconds=1)
    return now.isoformat()
