# Changelog

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

## 1.0.0b1 - 2026-06-12（未公开发布的内部 beta）

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
