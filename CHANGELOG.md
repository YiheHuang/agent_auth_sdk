# Changelog

## 1.0.0rc1 - 2026-07-15

首个正式版候选，保持 wire protocol v1 和 Registry schema 1：

- 单身份配置支持零参数 `OpenAIAgentAuth.from_env()`，同时保留 beta 多 role 配置兼容
- 支持注入 HTTP client、nonce store 和 metadata cache；相对 Vault CA 路径按 TOML 目录解析
- strict profile 要求固定 Vault key version；本地明文 Vault 只允许显式 loopback/test
- 新增 `[remotes.<alias>]` 与 `auth.remote_tool()`，减少重复 agent_id/URL
- 新增 `auth.router()`/`@router.endpoint()`，并支持直接 `app.include_router(router)`
- 远程请求传播 request ID，稳定错误 envelope 映射为 `AgentAuthError`
- Router/ASGI middleware 使用原始 path/query 和可配置 public base URL，拒绝重复签名 header
- Registry 启动拒绝未知 schema，新增 `db check` 与 SQLite online `db backup`
- 新增 live/ready health endpoint，旧写路由返回弃用 header
- OpenAI Agents 正式兼容范围收口为 `>=0.18.2,<0.19`，Python 增加 3.14
- 重写正式版 README、Quick Start、协议、安全、Registry 和 0.2→1.0 迁移文档

## 0.2.0b1 - 2026-07-11

OpenAI Agents 开发体验版本：

- 新增单身份 `OpenAIAgentAuth`，运行时加载不再隐式创建 key 或发布身份
- 新增保留原生 schema/metadata 的 `protect_tool()`、`agent_as_tool()` 和 `authenticated_handoff()`
- 新增类型化 `remote_agent_tool()` 与自动验签/签名响应的 `AgentAuthRouter`
- 新增 `AuthenticatedAgentContext`、稳定异常层级和无敏感 payload 的结构化事件
- 新增显式 `agent-auth provision`，strict profile 禁止认证旁路
- 新增只读 `agent-auth openai inspect` 和幂等 migration report
- OpenAI Agents CI 兼容范围固定为 `0.2.0` 至 `0.18.2`
- 旧 `AuthenticatedOpenAIAgents` 接口保留为兼容层

## 0.1.0b2 - 2026-07-11

文档、示例和公开 API 可用性版本：

- 重写 PyPI README，新增 Vault + HTTPS Registry 可运行 Quick Start
- 新增 SDK 全公开面 API Reference 和按任务组织的使用指南
- 新增本地消息/HTTP、Vault 发布、密钥生命周期和远程 ASGI examples
- 新增 OpenAI Agents 离线契约、真实模型和远程 HTTP server/client examples
- 扩写 Registry 的 PyPI 安装、systemd/Nginx、管理、备份恢复和排障手册
- 部署脚本默认支持固定版本 PyPI 安装，并保留显式 source 模式
- 将 Signer、协议模型、结果、Profile、存储和 Vault 扩展点从顶层非破坏性 re-export
- 将 docs、examples、Quick Start 和 deploy 资产纳入 SDK sdist

## 0.1.0b1 - 2026-07-10

首个准备公开发布的安全重构 beta：

- 修复首次发布可覆盖既有 Agent owner 的身份接管漏洞
- developer 绑定不可重叠的 domain/path namespace
- SDK、Redis、Registry SQLite 使用原子 nonce 消费
- strict timestamp、canonical JSON、DER ES256 与协议 golden vectors
- Registry 默认失败关闭，直接发现增加 DNS IP pinning 与 SSRF 防护
- Registry 写操作以 SQLite 事务提交 nonce、状态和审计，并拒绝过期并发更新
- HTTP/Registry 签名覆盖实际 body bytes，验签失败不泄漏底层解析异常
- 新增 `AgentVerifier`、`RegistryClient`、`RemoteAgentClient` 与 ASGI middleware
- Vault signer 固定 key version，token 隐藏且读取规则收紧
- 拆分 `verifiable-agent-auth-sdk` 与 `verifiable-agent-auth-registry` 两个发行包
- Registry HTTPS、非 root systemd、单 worker 和速率限制部署基线

## 1.0.0b1 - 2026-06-12（未公开发布的内部历史编号，不属于当前 SemVer 发布线）

首次 beta 版本，包含以下主要功能：

**Agent 身份管理**
- Agent Identity 创建 (`AgentInstance.from_vault()` / `AgentInstance.from_signer()`)
- Agent Metadata 导出 (`export_metadata()` -> `/.well-known/agent.json`)
- Agent ID 格式 `agent://{host}/{name}` 与解析 (`identity.py`)

**Registry 中心注册**
- 发布/更新 Agent metadata (`publish()`, `POST /registry/agents/publish`)
- Agent → Developer owner 绑定，不可变字段保护
- Registry 聚合文档 (`/.well-known/agent.json`) 自动生成
- API key PBKDF2-HMAC-SHA256 安全存储

**HTTP 请求签名与验签**
- HTTP 请求签名 (`sign_http()` → `x-agent-*` headers)
- HTTP 请求验签 (`verify_http_request()`，含 timestamp + nonce 防重放)
- 规范消息签名/验签 (`sign_message()` / `verify_agent_message()`)

**密钥生命周期管理**
- 密钥轮换 (`rotate_key()`，双签名证明：旧 key + 新 key proof)
- 添加额外活跃密钥 (`add_key()`，域名分离防跨操作重放)
- 密钥撤销 (`revoke_key()`，防锁死保护)
- Agent 撤销 (`revoke_agent()`，不可逆)

**HashiCorp Vault Transit 集成**
- Vault Transit ES256 签名 (`VaultTransitSigner`)
- 自动创建 ecdsa-p256 key (`auto_create_key=True`)
- 公钥解析与 PEM/base64url 双格式支持

**安全基础设施**
- STRICT / TEST 两种 RuntimeProfile
- InMemory / Redis NonceStore（防重放）
- InMemory / File(SQLite) MetadataCache
- 10 种验签错误码 (`VerificationErrorCode`)
- 自定义 Signer 协议支持 (`CallableSigner`)

**Registry 管理**
- FastAPI Registry 服务（6 个端点）
- SQLite 存储层（5 张表 + 审计日志）
- Admin CLI（`agent-auth-registry-admin`）
- CentOS/OpenCloudOS 一键部署脚本
- Nginx 反向代理配置
- Systemd 服务集成
