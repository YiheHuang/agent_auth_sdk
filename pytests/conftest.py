from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def dev_config(tmp_path: Path) -> Path:
    path = tmp_path / "agent-auth.toml"
    path.write_text(
        """version = 1
mode = "dev"

[agents.coordinator]
id = "agent://127.0.0.1/coordinator"
endpoint = "http://127.0.0.1:8101/invoke"
capabilities = ["coordinate"]

[agents.researcher]
id = "agent://127.0.0.1/researcher"
endpoint = "http://127.0.0.1:8102/invoke"
capabilities = ["research"]

[remotes]
researcher = "agent://127.0.0.1/researcher"
""",
        encoding="utf-8",
    )
    return path
