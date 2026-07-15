"""最小单节点 SQLite Registry storage。"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agent_auth._identity import namespace_matches
from agent_auth._types import AgentRecord

SCHEMA_VERSION = 1


class StateConflictError(RuntimeError):
    pass


class UnsupportedSchemaVersionError(RuntimeError):
    pass


@dataclass(slots=True, frozen=True)
class Developer:
    id: str
    client_id: str
    api_key_hash: str
    status: str


@dataclass(slots=True, frozen=True)
class Namespace:
    id: str
    developer_id: str
    domain: str
    path_prefix: str
    status: str


class RegistryStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
            ).fetchone()
            if existing:
                version = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
                if version not in {None, SCHEMA_VERSION}:
                    raise UnsupportedSchemaVersionError(
                        f"Unsupported Registry schema version {version}; expected {SCHEMA_VERSION}"
                    )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS developers (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL UNIQUE,
                    api_key_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS namespaces (
                    id TEXT PRIMARY KEY,
                    developer_id TEXT NOT NULL REFERENCES developers(id),
                    domain TEXT NOT NULL,
                    path_prefix TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS namespaces_active_unique
                    ON namespaces(domain, path_prefix) WHERE status='active';
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    developer_id TEXT NOT NULL REFERENCES developers(id),
                    endpoint TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    kid TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked'))
                );
                CREATE TABLE IF NOT EXISTS key_history (
                    kid TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                    public_key TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('current','inactive')),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS nonces (
                    sender TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY(sender, request_id)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    developer_id TEXT,
                    agent_id TEXT,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    code TEXT,
                    source_ip TEXT
                );
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, _now()),
            )

    def schema_status(self) -> dict[str, object]:
        with self._connect() as connection:
            version = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        return {
            "ok": version == SCHEMA_VERSION and integrity == "ok",
            "schema_version": version,
            "expected_schema_version": SCHEMA_VERSION,
            "integrity": integrity,
        }

    def backup(self, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as source, closing(sqlite3.connect(target)) as output:
            with output:
                source.backup(output)
        return target

    def create_developer(self, client_id: str, api_key_hash: str) -> Developer:
        developer = Developer(str(uuid.uuid4()), client_id, api_key_hash, "active")
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO developers(id, client_id, api_key_hash, status, created_at) VALUES (?,?,?,?,?)",
                    (developer.id, developer.client_id, developer.api_key_hash, developer.status, _now()),
                )
        except sqlite3.IntegrityError as exc:
            raise StateConflictError("CLIENT_ID_EXISTS") from exc
        return developer

    def get_developer(self, client_id: str) -> Developer | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM developers WHERE client_id=?", (client_id,)).fetchone()
        return _developer(row)

    def list_developers(self) -> list[Developer]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM developers ORDER BY client_id").fetchall()
        return [_developer(row) for row in rows if row is not None]  # type: ignore[misc]

    def rotate_developer_key(self, client_id: str, api_key_hash: str) -> None:
        with self._connect() as connection:
            changed = connection.execute(
                "UPDATE developers SET api_key_hash=? WHERE client_id=? AND status='active'",
                (api_key_hash, client_id),
            ).rowcount
        if not changed:
            raise StateConflictError("DEVELOPER_NOT_FOUND")

    def revoke_developer(self, client_id: str) -> None:
        with self._connect() as connection:
            changed = connection.execute(
                "UPDATE developers SET status='revoked' WHERE client_id=? AND status='active'", (client_id,)
            ).rowcount
        if not changed:
            raise StateConflictError("DEVELOPER_NOT_FOUND")

    def grant_namespace(self, developer_id: str, domain: str, path_prefix: str) -> Namespace:
        domain = domain.lower().strip()
        path_prefix = "/" + path_prefix.strip("/")
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT * FROM namespaces WHERE domain=? AND status='active'", (domain,)
            ).fetchall()
            for row in existing:
                current = str(row["path_prefix"])
                if (
                    current == path_prefix
                    or current.startswith(path_prefix + "/")
                    or path_prefix.startswith(current + "/")
                ):
                    raise StateConflictError("NAMESPACE_OVERLAP")
            namespace = Namespace(str(uuid.uuid4()), developer_id, domain, path_prefix, "active")
            connection.execute(
                "INSERT INTO namespaces(id, developer_id, domain, path_prefix, status, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (namespace.id, namespace.developer_id, domain, path_prefix, namespace.status, _now()),
            )
        return namespace

    def list_namespaces(self, client_id: str | None = None) -> list[Namespace]:
        query = "SELECT n.* FROM namespaces n JOIN developers d ON d.id=n.developer_id"
        parameters: tuple[str, ...] = ()
        if client_id:
            query += " WHERE d.client_id=?"
            parameters = (client_id,)
        query += " ORDER BY n.domain,n.path_prefix"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_namespace(row) for row in rows]

    def revoke_namespace(self, namespace_id: str) -> None:
        with self._connect() as connection:
            changed = connection.execute(
                "UPDATE namespaces SET status='revoked' WHERE id=? AND status='active'", (namespace_id,)
            ).rowcount
        if not changed:
            raise StateConflictError("NAMESPACE_NOT_FOUND")

    def has_namespace(self, developer_id: str, agent_id: str) -> bool:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT domain,path_prefix FROM namespaces WHERE developer_id=? AND status='active'",
                (developer_id,),
            ).fetchall()
        return any(namespace_matches(agent_id, row["domain"], row["path_prefix"]) for row in rows)

    def resolve(self, agent_id: str) -> AgentRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agents WHERE agent_id=? AND status='active'", (agent_id,)
            ).fetchone()
        return _record(row)

    def list_active_agents(self) -> list[AgentRecord]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM agents WHERE status='active' ORDER BY agent_id").fetchall()
        return [_record(row) for row in rows if row is not None]  # type: ignore[misc]

    def owner(self, agent_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute("SELECT developer_id FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return str(row[0]) if row else None

    def has_nonce(self, sender: str, request_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM nonces WHERE sender=? AND request_id=? AND expires_at>?",
                (sender, request_id, _now()),
            ).fetchone()
        return row is not None

    def publish(self, record: AgentRecord, developer_id: str, request_id: str, expires_at: str) -> AgentRecord:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _consume(connection, record.agent_id, request_id, expires_at)
            current = connection.execute("SELECT * FROM agents WHERE agent_id=?", (record.agent_id,)).fetchone()
            if current is None:
                if connection.execute("SELECT 1 FROM key_history WHERE kid=?", (record.kid,)).fetchone():
                    raise StateConflictError("KID_ALREADY_USED")
                connection.execute(
                    "INSERT INTO agents(agent_id,developer_id,endpoint,capabilities_json,kid,public_key,"
                    "updated_at,status) "
                    "VALUES (?,?,?,?,?,?,?,'active')",
                    (
                        record.agent_id,
                        developer_id,
                        record.endpoint,
                        json.dumps(list(record.capabilities), separators=(",", ":")),
                        record.kid,
                        record.public_key,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO key_history(kid,agent_id,public_key,status,created_at) VALUES (?,?,?,'current',?)",
                    (record.kid, record.agent_id, record.public_key, now),
                )
            else:
                if current["developer_id"] != developer_id:
                    raise StateConflictError("OWNER_MISMATCH")
                if current["status"] != "active":
                    raise StateConflictError("AGENT_REVOKED")
                if current["kid"] != record.kid or current["public_key"] != record.public_key:
                    raise StateConflictError("PUBLISH_CANNOT_CHANGE_KEY")
                connection.execute(
                    "UPDATE agents SET endpoint=?,capabilities_json=?,updated_at=? WHERE agent_id=?",
                    (
                        record.endpoint,
                        json.dumps(list(record.capabilities), separators=(",", ":")),
                        now,
                        record.agent_id,
                    ),
                )
            _audit(connection, developer_id, record.agent_id, "publish", "accepted", None, None)
        result = self.resolve(record.agent_id)
        if result is None:  # pragma: no cover - transaction invariant
            raise RuntimeError("published Agent missing")
        return result

    def rotate(
        self,
        *,
        agent_id: str,
        developer_id: str,
        current_kid: str,
        new_kid: str,
        new_public_key: str,
        request_ids: tuple[str, str],
        expires_at: str,
    ) -> AgentRecord:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for request_id in request_ids:
                _consume(connection, agent_id, request_id, expires_at)
            row = connection.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if row is None:
                raise StateConflictError("AGENT_NOT_FOUND")
            if row["developer_id"] != developer_id:
                raise StateConflictError("OWNER_MISMATCH")
            if row["status"] != "active" or row["kid"] != current_kid:
                raise StateConflictError("CURRENT_KEY_MISMATCH")
            if connection.execute("SELECT 1 FROM key_history WHERE kid=?", (new_kid,)).fetchone():
                raise StateConflictError("KID_ALREADY_USED")
            connection.execute("UPDATE key_history SET status='inactive' WHERE kid=?", (current_kid,))
            connection.execute(
                "INSERT INTO key_history(kid,agent_id,public_key,status,created_at) VALUES (?,?,?,'current',?)",
                (new_kid, agent_id, new_public_key, now),
            )
            connection.execute(
                "UPDATE agents SET kid=?,public_key=?,updated_at=? WHERE agent_id=?",
                (new_kid, new_public_key, now, agent_id),
            )
            _audit(connection, developer_id, agent_id, "rotate", "accepted", None, None)
        result = self.resolve(agent_id)
        if result is None:  # pragma: no cover
            raise RuntimeError("rotated Agent missing")
        return result

    def revoke(
        self,
        *,
        agent_id: str,
        developer_id: str,
        current_kid: str,
        request_id: str,
        expires_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _consume(connection, agent_id, request_id, expires_at)
            row = connection.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if row is None:
                raise StateConflictError("AGENT_NOT_FOUND")
            if row["developer_id"] != developer_id:
                raise StateConflictError("OWNER_MISMATCH")
            if row["status"] != "active" or row["kid"] != current_kid:
                raise StateConflictError("CURRENT_KEY_MISMATCH")
            connection.execute("UPDATE agents SET status='revoked',updated_at=? WHERE agent_id=?", (_now(), agent_id))
            connection.execute("UPDATE key_history SET status='inactive' WHERE kid=?", (current_kid,))
            _audit(connection, developer_id, agent_id, "revoke", "accepted", None, None)

    def admin_revoke_agent(self, agent_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE agents SET status='revoked',updated_at=? WHERE agent_id=? AND status='active'",
                (_now(), agent_id),
            ).rowcount
            if changed:
                connection.execute("UPDATE key_history SET status='inactive' WHERE agent_id=?", (agent_id,))
                _audit(connection, None, agent_id, "admin.revoke", "accepted", None, None)
        if not changed:
            raise StateConflictError("AGENT_NOT_FOUND")

    def write_audit(
        self,
        *,
        developer_id: str | None,
        agent_id: str | None,
        action: str,
        result: str,
        code: str | None,
        source_ip: str | None,
    ) -> None:
        with self._connect() as connection:
            _audit(connection, developer_id, agent_id, action, result, code, source_ip)

    def readiness(self) -> bool:
        try:
            status = self.schema_status()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("CREATE TEMP TABLE IF NOT EXISTS readiness(value INTEGER)")
            return bool(status["ok"])
        except sqlite3.Error:
            return False


def _consume(connection: sqlite3.Connection, sender: str, request_id: str, expires_at: str) -> None:
    connection.execute("DELETE FROM nonces WHERE expires_at <= ?", (_now(),))
    try:
        connection.execute(
            "INSERT INTO nonces(sender,request_id,expires_at) VALUES (?,?,?)",
            (sender, request_id, expires_at),
        )
    except sqlite3.IntegrityError as exc:
        raise StateConflictError("NONCE_REPLAYED") from exc


def _audit(
    connection: sqlite3.Connection,
    developer_id: str | None,
    agent_id: str | None,
    action: str,
    result: str,
    code: str | None,
    source_ip: str | None,
) -> None:
    connection.execute(
        "INSERT INTO audit(created_at,developer_id,agent_id,action,result,code,source_ip) VALUES (?,?,?,?,?,?,?)",
        (_now(), developer_id, agent_id, action, result, code, source_ip),
    )


def _developer(row: sqlite3.Row | None) -> Developer | None:
    return Developer(row["id"], row["client_id"], row["api_key_hash"], row["status"]) if row else None


def _namespace(row: sqlite3.Row) -> Namespace:
    return Namespace(row["id"], row["developer_id"], row["domain"], row["path_prefix"], row["status"])


def _record(row: sqlite3.Row | None) -> AgentRecord | None:
    if row is None:
        return None
    capabilities = json.loads(row["capabilities_json"])
    return AgentRecord(
        agent_id=row["agent_id"],
        endpoint=row["endpoint"],
        capabilities=tuple(capabilities),
        kid=row["kid"],
        public_key=row["public_key"],
        updated_at=row["updated_at"],
    )


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
