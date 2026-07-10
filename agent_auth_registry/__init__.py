"""源码仓库兼容 shim；正式 Registry 包位于 packages/agent-auth-registry。"""

from pathlib import Path

_source_package = (
    Path(__file__).resolve().parent.parent
    / "packages"
    / "agent-auth-registry"
    / "src"
    / "agent_auth_registry"
)
if _source_package.is_dir():
    __path__.append(str(_source_package))
