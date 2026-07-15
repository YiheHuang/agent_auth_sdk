"""防重放状态；production 使用 SQLite，dev 使用内存。"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

_INITIALIZE_LOCK = threading.Lock()


class NonceState(Protocol):
    def consume(self, sender: str, request_id: str, expires_at: datetime) -> bool: ...


class MemoryNonceState:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def consume(self, sender: str, request_id: str, expires_at: datetime) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            self._values = {key: expiry for key, expiry in self._values.items() if expiry > now}
            key = (sender, request_id)
            if key in self._values:
                return False
            self._values[key] = expires_at
            return True


class SQLiteNonceState:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _INITIALIZE_LOCK:
            with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA busy_timeout=5000")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS nonces (sender TEXT NOT NULL, request_id TEXT NOT NULL, "
                    "expires_at TEXT NOT NULL, PRIMARY KEY(sender, request_id))"
                )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def consume(self, sender: str, request_id: str, expires_at: datetime) -> bool:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
            try:
                connection.execute(
                    "INSERT INTO nonces(sender, request_id, expires_at) VALUES (?, ?, ?)",
                    (sender, request_id, expires_at.isoformat()),
                )
            except sqlite3.IntegrityError:
                return False
        return True
