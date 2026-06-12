"""缓存与 nonce 存储实现。"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

from redis.asyncio import Redis

from .models import AgentMetadata, ResolveResult


class NonceStore(Protocol):
    async def has(self, key: str) -> bool: ...

    async def set(self, key: str, ttl_seconds: int) -> None: ...


class MetadataCache(Protocol):
    async def get(self, agent_id: str) -> ResolveResult | None: ...

    async def set(self, agent_id: str, result: ResolveResult, ttl_seconds: int) -> None: ...


class InMemoryNonceStore(NonceStore):
    def __init__(self) -> None:
        self._entries: dict[str, datetime] = {}

    async def has(self, key: str) -> bool:
        self._sweep()
        return key in self._entries

    async def set(self, key: str, ttl_seconds: int) -> None:
        self._entries[key] = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._sweep()

    def _sweep(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)


class RedisNonceStore(NonceStore):
    def __init__(self, redis_client: Redis, *, prefix: str = "agent_identity:nonce:") -> None:
        self._redis = redis_client
        self._prefix = prefix

    async def has(self, key: str) -> bool:
        return bool(await self._redis.exists(self._prefix + key))

    async def set(self, key: str, ttl_seconds: int) -> None:
        await self._redis.set(self._prefix + key, "1", ex=ttl_seconds)


class InMemoryMetadataCache(MetadataCache):
    def __init__(self) -> None:
        self._entries: dict[str, tuple[ResolveResult, datetime]] = {}

    async def get(self, agent_id: str) -> ResolveResult | None:
        self._sweep()
        entry = self._entries.get(agent_id)
        if not entry:
            return None
        return entry[0]

    async def set(self, agent_id: str, result: ResolveResult, ttl_seconds: int) -> None:
        self._entries[agent_id] = (
            result,
            datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
        self._sweep()

    def _sweep(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [key for key, (_, expires_at) in self._entries.items() if expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)


class FileMetadataCache(MetadataCache):
    """用 SQLite 持久化 metadata 缓存，便于本地调试与重启恢复。"""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata_cache (
                    agent_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    resolved_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    etag TEXT,
                    source_url TEXT
                )
                """,
            )

    async def get(self, agent_id: str) -> ResolveResult | None:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                """
                SELECT payload, resolved_at, expires_at, etag, source_url
                FROM metadata_cache
                WHERE agent_id = ?
                """,
                (agent_id,),
            ).fetchone()
        if not row:
            return None
        payload, resolved_at, expires_at, etag, source_url = row
        if datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
            return None
        return ResolveResult(
            metadata=AgentMetadata.model_validate_json(payload),
            resolved_at=datetime.fromisoformat(resolved_at),
            etag=etag,
            source_url=source_url,
        )

    async def set(self, agent_id: str, result: ResolveResult, ttl_seconds: int) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO metadata_cache(agent_id, payload, resolved_at, expires_at, etag, source_url)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    payload = excluded.payload,
                    resolved_at = excluded.resolved_at,
                    expires_at = excluded.expires_at,
                    etag = excluded.etag,
                    source_url = excluded.source_url
                """,
                (
                    agent_id,
                    result.metadata.model_dump_json(),
                    result.resolved_at.isoformat(),
                    expires_at.isoformat(),
                    result.etag,
                    result.source_url,
                ),
            )

