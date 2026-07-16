# Release checklist

两个包必须使用同一版本发布，Registry 精确依赖该版本 SDK。

## 版本改动清单

- `pyproject.toml`：SDK 版本、依赖、extras、包 include/exclude。
- `agent_auth/__init__.py`：fallback 版本和 `__all__`。
- `packages/agent-auth-registry/pyproject.toml`：Registry 版本及 SDK 精确依赖。
- `README.md`、`QUICKSTART.md`、Registry README、示例和部署手册中的安装版本。
- `CHANGELOG.md`、`SECURITY.md` 支持范围。
- `.github/workflows/*.yml` 的 TestPyPI/兼容矩阵版本（如有变化）。

## 必须通过

```bash
python -m ruff check agent_auth packages/agent-auth-registry/src pytests examples
python -m ruff format --check agent_auth packages/agent-auth-registry/src pytests examples
python -m mypy agent_auth packages/agent-auth-registry/src
python -m pytest
python -m build --sdist --wheel
python -m build --sdist --wheel packages/agent-auth-registry
python -m twine check --strict dist/* packages/agent-auth-registry/dist/*
```

另需完成：

- Python 3.11–3.14、Windows/Linux CI。
- OpenAI Agents 0.18.2 与 `<0.19` 最新版契约测试。
- 协议/nonce/Registry mutation 分支覆盖率至少 95%，全项目至少 85%。
- 基础 SDK 直接依赖恰好两个；公开类型不超过三个；SDK CLI 和 Registry 路由各五个。
- 在干净虚拟环境安装两个 wheel，执行两个 CLI smoke test和离线 OpenAI 示例。
- 检查 sdist/wheel 不含运行数据库、token、内部笔记或缓存。
- 使用本地 wheel 完成真实 Vault + Registry + OpenAI WebApp 验证；发布后从正式 PyPI 干净安装复验。
- 确认工作树干净、tag 与版本一致后，使用 PyPI Trusted Publishing 发布。

`1.1.0` 与 `1.0.0` Registry schema/wire protocol 兼容；新增 local mode 和 `AgentAuth.call()` 不要求迁移数据。
