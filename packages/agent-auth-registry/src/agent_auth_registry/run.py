"""Registry server entrypoint。"""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-auth-registry")
    parser.add_argument("--host", default=os.getenv("AGENT_REGISTRY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("AGENT_REGISTRY_PORT", "8008")))
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("uvicorn is required") from exc
    uvicorn.run(
        "agent_auth_registry.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        workers=1,
        proxy_headers=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
