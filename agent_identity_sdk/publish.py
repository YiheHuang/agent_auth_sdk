"""用于生成、落盘和导出 well-known metadata。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import AgentAuditConfig, AgentKey, AgentMetadata


def render_agent_metadata(
    *,
    agent_id: str,
    domain: str,
    name: str,
    organization: str,
    endpoint: str,
    capabilities: list[str],
    keys: list[AgentKey],
    revoked_kids: list[str] | None = None,
    environment: str | None = None,
    signing_policy: dict | None = None,
    verification_policy: dict | None = None,
    audit: AgentAuditConfig | None = None,
) -> AgentMetadata:
    return AgentMetadata(
        version="1.0",
        agent_id=agent_id,
        domain=domain,
        name=name,
        organization=organization,
        endpoint=endpoint,
        capabilities=capabilities,
        keys=keys,
        revoked_kids=revoked_kids or [],
        updated_at=datetime.now(timezone.utc),
        environment=environment,
        signing_policy=signing_policy,
        verification_policy=verification_policy,
        audit=audit,
    )


def export_well_known(metadata: AgentMetadata, output_dir: str | Path) -> Path:
    target_dir = Path(output_dir) / ".well-known"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "agent.json"
    target_file.write_text(
        json.dumps(metadata.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return target_file

