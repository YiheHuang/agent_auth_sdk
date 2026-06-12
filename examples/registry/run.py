from __future__ import annotations

import os

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "examples.registry.app:app",
        host=os.getenv("AGENT_REGISTRY_HOST", "0.0.0.0"),
        port=int(os.getenv("AGENT_REGISTRY_PORT", "8008")),
        reload=False,
    )
