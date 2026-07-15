# 版本与代码修改检查清单

本清单供维护者在修改代码、文档、协议、依赖或准备新版本时使用。并非每项都需要修改，但每项都应判断是否受影响。

## 1. 开始修改前

- [ ] 明确改动类型：内部实现、公开 API、wire protocol、Registry schema/API、OpenAI integration、部署或纯文档。
- [ ] 确认工作区状态，避免覆盖无关改动：`git status --short`。
- [ ] 确认目标 Python 和 OpenAI Agents 支持矩阵是否变化。
- [ ] 涉及安全边界时，先补回归测试，再修改实现。
- [ ] 不在代码、示例、测试 fixture、文档或日志中写入真实 API key、Vault token、私钥和公网凭证。

## 2. 任何代码修改

- [ ] 修改或新增对应单元测试、集成测试和失败路径测试。
- [ ] 检查 `README.md`、`QUICKSTART.md`、`docs/SDK_GUIDE.md` 和 examples 是否仍与实际行为一致。
- [ ] 检查异常类型、稳定 `VerificationFailure.code` 和错误文本是否发生变化。
- [ ] 检查 async client、Vault client、cache、nonce store 的生命周期是否正确关闭。
- [ ] 检查 Windows/Linux 和 Python 3.11–3.14 差异。
- [ ] 执行 Ruff、格式、Mypy 和完整 pytest。

## 3. 公开 API 修改

可能需要同步修改：

- [ ] `agent_auth_sdk/__init__.py`：顶层 import、`__all__` 和 fallback version。
- [ ] `agent_auth_sdk/integrations/__init__.py`：integration 导出。
- [ ] `docs/API_REFERENCE.md`：签名、参数、返回值、错误和最小示例。
- [ ] `docs/SDK_GUIDE.md`：推荐使用路径和迁移说明。
- [ ] `README.md` 与 `QUICKSTART.md`：最短路径是否使用了变更接口。
- [ ] `examples/`：至少一个示例覆盖新增或修改的公开能力。
- [ ] `pytests/test_examples_and_docs.py`：公开导出文档覆盖检查。
- [ ] `CHANGELOG.md`：标明新增、弃用或破坏性变化。

如果移除或重命名公开接口：

- [ ] Beta 阶段也要给出迁移方式；能保留兼容别名时先弃用，不直接删除。
- [ ] 判断是否需要升级 minor/major，而不是只升级 beta 序号。

## 4. 签名协议或安全语义修改

可能需要同步修改：

- [ ] `docs/PROTOCOL_V1.md`。
- [ ] `docs/protocol-v1-vectors.json` 和 golden vector 测试。
- [ ] `docs/SECURITY_MODEL.md`：信任根、已防御威胁和不提供的保证。
- [ ] `agent_auth_sdk/signing.py`、`messaging.py`、`verification.py`、`registry_security.py`。
- [ ] Registry 对应验签逻辑和状态码。
- [ ] 篡改、timestamp、recipient、nonce replay、kid 撤销等安全回归测试。
- [ ] 跨实现兼容性和旧消息/旧签名是否继续可验证。

协议 v1 已声明冻结。若 canonical 格式、必需 headers、算法、timestamp 或 signature encoding 改变，应创建新协议版本，不静默改变 v1。

## 5. Registry 修改

### HTTP API、状态或 namespace

- [ ] `packages/agent-auth-registry/src/agent_auth_registry/app.py`。
- [ ] `agent_auth_sdk/registry_client.py` 和底层 publish client。
- [ ] `docs/REGISTRY_OPERATIONS.md` 的 endpoint、request/response、状态码和排障。
- [ ] `packages/agent-auth-registry/README.md`。
- [ ] Nginx location、rate limit、body limit 是否需要变化。
- [ ] publish、resolve、add、rotate、revoke 和 ownership 安全测试。

### SQLite schema 或事务

- [ ] `packages/agent-auth-registry/src/agent_auth_registry/storage.py`。
- [ ] schema version 和迁移/新建数据库策略。
- [ ] 事务中断、并发写、重启恢复、备份恢复测试。
- [ ] 部署手册的升级、回滚和备份说明。
- [ ] 是否仍满足单节点、单 worker 限制；不得无意宣称 HA。

### Admin CLI

- [ ] `packages/agent-auth-registry/src/agent_auth_registry/admin.py`。
- [ ] Registry 运维手册的命令表、参数和输出说明。
- [ ] CLI smoke test 和敏感输出检查。

## 6. Vault 或密钥生命周期修改

- [ ] `agent_auth_sdk/vault_kms.py` 和 `AgentInstance` 生命周期方法。
- [ ] Vault policy 路径、token 文件权限、namespace、TLS/CA 文档。
- [ ] `QUICKSTART.md`、`examples/vault_registry_quickstart.py` 和 `examples/key_lifecycle.py`。
- [ ] key version 固定、kid 唯一、add/rotate/revoke/current key 语义测试。
- [ ] 权限失败、404 创建条件、网络失败和并发签名测试。
- [ ] 确认 raw token 不出现在 repr、异常和日志中。

## 7. OpenAI Agents 集成修改

- [ ] 使用官方 OpenAI Agents 文档核对 `Agent`、`Runner.run`、`function_tool` 和模型配置。
- [ ] `agent_auth_sdk/integrations/openai_agents.py`。
- [ ] `docs/OPENAI_AGENTS.md`。
- [ ] `examples/openai_agents/offline_local.py`、live 和 remote 示例。
- [ ] `.github/workflows/ci.yml` 中最低/最新 `openai-agents` 兼容矩阵。
- [ ] 真实 SDK contract test；不得静默 fallback 到 Fake Agent/Runner。
- [ ] 明确 local wrapper 与远程 HTTP 边界的不同安全保证。
- [ ] 不硬编码易过时模型；使用官方推荐的环境变量或显式用户配置。

## 8. 依赖修改

可能需要同步修改：

- [ ] 根 `pyproject.toml` 的 dependencies/extras/dev dependencies。
- [ ] Registry `pyproject.toml` 的服务端依赖和精确 SDK 依赖。
- [ ] README 安装矩阵和 examples 安装命令。
- [ ] Python/OpenAI/Redis/Vault 支持范围文档。
- [ ] 在干净 venv 中安装所有 extras，并执行 `pip check`。
- [ ] 在隔离环境执行 dependency audit，避免审计全局无关工具。
- [ ] 检查新增依赖许可证、维护状态、wheel 可用性和 Python 版本支持。

## 9. 部署资产修改

- [ ] `deploy/deploy-registry.sh`：PyPI/source 模式、默认版本、权限和 purge 行为。
- [ ] `deploy/registry.service`：User、路径、EnvironmentFile、ReadWritePaths 和 hardening。
- [ ] `deploy/nginx.agent-auth.conf`：TLS、proxy headers、body limit、rate limit 和安全 headers。
- [ ] `deploy/registry.env.example`：所有环境变量及安全默认值。
- [ ] `docs/REGISTRY_OPERATIONS.md` 和 `deploy/DEPLOY_BETA_V1.md`。
- [ ] `bash -n deploy/deploy-registry.sh`。
- [ ] 可用时运行 `systemd-analyze verify` 和替换真实测试证书后的 `nginx -t`。

## 10. 版本号更新

SDK 与 Registry 必须同步版本。将下列位置从旧版本替换为新版本：

- [ ] 根 `pyproject.toml`：SDK `project.version`。
- [ ] Registry `pyproject.toml`：Registry `project.version`。
- [ ] Registry `pyproject.toml`：`verifiable-agent-auth-sdk==新版本`。
- [ ] `agent_auth_sdk/__init__.py`：源码树 fallback `__version__`。
- [ ] `.github/workflows/test-publish.yml`：默认测试版本。
- [ ] `CHANGELOG.md`：新版本日期和变更摘要。
- [ ] `README.md`、`QUICKSTART.md`、Registry README 中显示或固定安装的版本。
- [ ] `docs/OPENAI_AGENTS.md`、`docs/REGISTRY_OPERATIONS.md` 等固定安装命令。
- [ ] `deploy/deploy-registry.sh` 的默认 `AGENT_AUTH_VERSION`。
- [ ] `deploy/DEPLOY_BETA_V1.md` 和 examples 文档中的固定版本。

替换后检查残留：

```bash
rg -n "旧版本号" \
  pyproject.toml packages agent_auth_sdk .github \
  README.md QUICKSTART.md CHANGELOG.md docs deploy examples
```

历史 CHANGELOG 中的旧版本标题应保留，不要机械替换。

## 11. 打包内容

- [ ] 根 `pyproject.toml` 的 sdist include/exclude 与新增文档、examples、deploy 资产一致。
- [ ] Registry sdist 只包含 Registry 运行代码、README、LICENSE 和 pyproject。
- [ ] wheel 不包含 docs、examples、测试、runtime、缓存或内部笔记。
- [ ] sdist 不包含 `next_step`、`.pkg-audit`、`.pytest_cache`、`__pycache__`、运行数据库和 token。
- [ ] README 中用于 PyPI 的链接都是绝对 GitHub/文档链接。
- [ ] Project URLs 包含 Documentation、Changelog、Security、Source 和 Issues。

构建检查：

```bash
python -m build --sdist --wheel
python -m build --sdist --wheel packages/agent-auth-registry
python -m twine check --strict dist/* packages/agent-auth-registry/dist/*
```

## 12. 发布前质量门槛

- [ ] Python 3.11、3.12、3.13、3.14，Linux/Windows CI 全绿。
- [ ] `python -m ruff check agent_auth_sdk packages/agent-auth-registry/src pytests examples`。
- [ ] `python -m ruff format --check agent_auth_sdk packages/agent-auth-registry/src pytests examples`。
- [ ] `python -m mypy agent_auth_sdk`。
- [ ] 完整测试通过，总分支覆盖率不低于 80%。
- [ ] messaging、verification、stores、registry_security 安全核心分支覆盖率不低于 95%。
- [ ] OpenAI Agents 最低和最新受支持版本 contract test 通过。
- [ ] 本地消息、HTTP 和 OpenAI 离线 examples 在干净 wheel 环境执行成功。
- [ ] 三个 CLI 的 `--help` 和关键 admin 命令 smoke test 通过。
- [ ] 干净环境安装两个 wheel 后 `pip check` 通过。
- [ ] 隔离依赖审计无已知漏洞。
- [ ] `git diff --check` 无错误，`git status` 中没有意外文件。

## 13. TestPyPI 与正式 PyPI

### TestPyPI

- [ ] 提交并推送版本更新，等待 CI 全绿。
- [ ] 运行 `Publish to TestPyPI`，版本输入与两个 pyproject 完全一致。
- [ ] 正常新版本保持 `upload_packages=true`。
- [ ] clean-install job 只从 TestPyPI 下载本项目 wheel，再从正式 PyPI 安装第三方依赖。
- [ ] 从全新环境安装并验证版本、imports、CLI 和 examples。

### 正式 PyPI

- [ ] 确认 `pypi` 和 `pypi-registry` Environment 允许 `v*` Tag 并配置审批。
- [ ] 创建 Tag `v新版本`，Target 为已通过 CI 的 `main` commit。
- [ ] Beta 版本勾选 GitHub Pre-release。
- [ ] 发布 Release 后审核并批准两个 Environment deployment。
- [ ] 只重跑失败的 publish job，不重复运行已经成功上传的包。
- [ ] 检查两个 PyPI 页面、依赖、README、Project URLs、wheel 和 sdist。
- [ ] 从正式 PyPI 在全新 venv 安装精确版本并运行 `pip check`、imports 和 CLI。

PyPI 文件和版本不可覆盖。如果任何文件已上传，修复后必须升级版本号，不能删除后复用原文件名。

## 14. 发布后

- [ ] 确认 GitHub Release、Tag、PyPI 两个项目和 CHANGELOG 版本一致。
- [ ] 确认 Registry 包安装时自动解析到精确配套 SDK 版本。
- [ ] 记录已知限制和升级注意事项。
- [ ] 如有部署变更，在非生产环境完成一次安装、升级、备份和恢复演练。
- [ ] 不再修改已发布 Tag；后续修复进入新版本。
