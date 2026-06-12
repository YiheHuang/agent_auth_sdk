"""启动本地 LLM Gateway。"""

from __future__ import annotations

import uvicorn

from .app import create_app, load_settings


def main() -> None:
    settings = load_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()

