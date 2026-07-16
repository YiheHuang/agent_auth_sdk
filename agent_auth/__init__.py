"""Agent Auth 的最小公开 API。"""

from importlib.metadata import PackageNotFoundError, version

from ._auth import AgentAuth
from ._errors import AgentAuthError
from ._types import AuthContext

__all__ = ["AgentAuth", "AuthContext", "AgentAuthError", "__version__"]

try:
    __version__ = version("verifiable-agent-auth-sdk")
except PackageNotFoundError:  # pragma: no cover - source checkout
    __version__ = "1.1.0"
