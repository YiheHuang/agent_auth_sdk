"""生产身份检查与发布：调用安装后的五命令 CLI。"""

from __future__ import annotations

import subprocess

if __name__ == "__main__":
    checked = subprocess.run(["agent-auth", "check"], check=False)  # noqa: S603,S607
    if checked.returncode:
        raise SystemExit(checked.returncode)
    raise SystemExit(subprocess.run(["agent-auth", "publish"], check=False).returncode)  # noqa: S603,S607
