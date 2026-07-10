from __future__ import annotations

import argparse
import os

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the single-node Agent Auth Registry")
    parser.add_argument("--host", default=os.getenv("AGENT_REGISTRY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("AGENT_REGISTRY_PORT", "8008")))
    parser.add_argument("--workers", type=int, default=int(os.getenv("AGENT_REGISTRY_WORKERS", "1")))
    args = parser.parse_args()
    if args.workers != 1:
        raise RuntimeError("Registry v1 supports exactly one worker; use AGENT_REGISTRY_WORKERS=1")
    uvicorn.run(
        "agent_auth_registry.app:app",
        host=args.host,
        port=args.port,
        reload=False,
        workers=args.workers,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


if __name__ == "__main__":
    main()
