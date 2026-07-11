"""不记录 payload 或凭证的结构化 Agent Auth 事件。"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True, frozen=True)
class AgentAuthEvent:
    operation: str
    source_agent_id: str | None
    target_agent_id: str | None
    ok: bool
    duration_ms: float
    code: str = "OK"
    request_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


EventSink = Callable[[AgentAuthEvent], None | Awaitable[None]]


async def emit_event(sink: EventSink | None, event: AgentAuthEvent) -> None:
    if sink is None:
        return
    result = sink(event)
    if inspect.isawaitable(result):
        await result
