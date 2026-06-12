"""审计日志与 SQLite 存储。"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditStore:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    agent_id TEXT,
                    kid TEXT,
                    verification_result TEXT NOT NULL,
                    llm_model TEXT,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """,
            )

    def log(
        self,
        *,
        request_id: str,
        agent_id: str | None,
        kid: str | None,
        verification_result: str,
        llm_model: str | None,
        payload: dict[str, Any],
    ) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs(request_id, agent_id, kid, verification_result, llm_model, created_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    agent_id,
                    kid,
                    verification_result,
                    llm_model,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(payload, ensure_ascii=False),
                ),
            )

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT request_id, agent_id, kid, verification_result, llm_model, created_at, payload
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result = []
        for row in rows:
            request_id, agent_id, kid, verification_result, llm_model, created_at, payload = row
            result.append(
                {
                    "request_id": request_id,
                    "agent_id": agent_id,
                    "kid": kid,
                    "verification_result": verification_result,
                    "llm_model": llm_model,
                    "created_at": created_at,
                    "payload": json.loads(payload),
                },
            )
        return result

