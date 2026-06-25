# Agent Auth SDK

`agent-auth-sdk` 是一个面向多 Agent 系统的身份认证 SDK。它提供 Agent metadata 发布、Vault Transit 私钥托管、Registry 公钥发现、HTTP/消息签名验签、nonce 防重放、key rotation/revoke，以及面向 OpenAI Agents SDK 的轻量显式接入层。

当前版本：`1.0.0b1`

## 适用场景

- 为每个 Agent 建立稳定身份：`agent://{domain}/{role}`
- 将 Agent metadata 和公钥发布到中心 Registry
- 私钥保留在开发者本地 Vault Transit 中，不导出
- 在跨 Agent 调用边界验证“谁调用了谁、payload 是否被篡改、结果是否可信”
- 在 OpenAI Agents SDK 项目里，用很少的代码改动接入认证

## 安装

```powershell
cd D:\FDU\agent_auth\agent_auth_sdk
pip install -e .
```

安装后可使用 CLI：

```powershell
agent-auth --help
agent-auth integrate-openai-agents --help
```

## 文档地图

- [API_REFERENCE.md](docs/API_REFERENCE.md): 核心 SDK API 和 OpenAI Agents 集成接口
- [OPENAI_AGENTS_INTEGRATION.md](docs/OPENAI_AGENTS_INTEGRATION.md): OpenAI Agents SDK 轻量接入指南
- [VAULT_SETUP.md](docs/VAULT_SETUP.md): Vault Transit 环境配置
- [REGISTRY_AGENT_JSON.md](docs/REGISTRY_AGENT_JSON.md): Registry `agent.json` 文档结构
- [agent_auth_demo_simple_integration](../agent_auth_demo_simple_integration): 三个轻量接入 demo
- [agent_auth_agents_demoproject](../agent_auth_agents_demoproject): 更完整的 OpenAI Agents SDK 认证 demo

## 核心概念

### Agent 身份

每个 Agent 都有一个稳定 ID：

```text
agent://127.0.0.1:8711/security
```

其中 host/domain 用于 metadata 发现，path 末尾通常对应 role 名。

### Metadata 与 Registry

Agent metadata 包含：

- `agent_id`
- domain/name/organization/endpoint
- capabilities
- public keys
- signing/verification policy

开发者将 metadata 发布到中心 Registry 后，其他 Agent 可以通过 Registry 解析发送方公钥并完成验签。

### Vault Transit

生产/真实模式下，私钥由 Vault Transit 管理：

- SDK 只读取公钥
- 签名通过 Vault Transit API 完成
- 私钥不可导出

### 跨 Agent 调用认证

原始跨 Agent 调用：

```text
Runner.run(target_agent, payload)
```

接入后：

```text
source 签名请求
target 验证请求
Runner.run(target_agent, payload)
target 签名结果
source 验证结果
返回可信 payload
```

开发者不需要手写签名协议，OpenAI Agents SDK 项目只需要在跨 Agent tool 边界调用 `auth.call_agent(...)`。

## OpenAI Agents SDK 轻量接入

### 1. 生成接入脚手架

```powershell
agent-auth integrate-openai-agents `
  --project-root . `
  --roles coordinator,security,architecture `
  --mode vault `
  --domain 127.0.0.1:8711 `
  --organization "Agent Auth Simple Original" `
  --registry-url http://192.144.228.237/.well-known/agent.json `
  --registry-publish-url http://192.144.228.237/registry/agents/publish `
  --role-capability coordinator:review.coordinate `
  --role-capability security:review.security `
  --role-capability architecture:review.architecture
```

CLI 会生成：

```text
.agent-auth/
  agent-auth.toml
  auth_adapter.py
  env.local.example
  env.vault.example
  INTEGRATION_REPORT.md
```

CLI 不修改业务源码。

### 2. 填写真实环境

在项目中新增或复制环境文件，例如 `.agent-auth/env.vault.ps1`：

```powershell
$env:AGENT_AUTH_ENABLED = "1"
$env:AGENT_AUTH_MODE = "vault"

$env:AGENT_AUTH_REGISTRY_CLIENT_ID = "your-client-id"
$env:AGENT_AUTH_REGISTRY_API_KEY = "your-api-key"

$env:AGENT_AUTH_VAULT_ADDR = "http://127.0.0.1:8300"
$env:AGENT_AUTH_VAULT_TOKEN_FILE = "D:\path\to\vault-token.txt"
$env:AGENT_AUTH_VAULT_TRANSIT_MOUNT = "transit"

$env:AGENT_AUTH_COORDINATOR_KEY_NAME = "my-coordinator-key"
$env:AGENT_AUTH_SECURITY_KEY_NAME = "my-security-key"
```

### 3. 在 tool 边界显式接入

原始代码：

```python
@function_tool
async def run_security_review(payload: dict) -> dict:
    return await Runner.run(security, payload)
```

接入后：

```python
auth = await get_auth_adapter()

@function_tool
async def run_security_review(payload: dict) -> dict:
    return await auth.call_agent(
        source_role="coordinator",
        target_role="security",
        target_agent=security,
        payload=payload,
        runner=Runner.run,
    )
```

这就是主要改动。Agent 定义、`function_tool`、`Runner.run`、payload 结构和业务 handler 都保持原样。

### 4. 运行

```powershell
. .\.agent-auth\env.vault.ps1
python -m your_project.app
```

输出中可以记录：

```json
"trusted_interactions": [
  "coordinator -> security -> coordinator verified"
]
```

详细说明见 [OPENAI_AGENTS_INTEGRATION.md](docs/OPENAI_AGENTS_INTEGRATION.md)。

## 核心 SDK 快速示例

### 创建 Agent

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.from_vault(
    domain="agent.example.com",
    name="weather",
    organization="Example Lab",
    endpoint="https://agent.example.com/tasks/handle",
    vault_addr="https://vault.example.com",
    vault_token_file="runtime/vault-token.txt",
    transit_mount="transit",
    key_name="weather-agent",
    capabilities=["weather.query", "sign", "verify"],
    auto_create_key=True,
)
```

### 发布到 Registry

```python
await agent.publish(
    registry_url="https://registry.example.com/registry/agents/publish",
    client_id="developer-a",
    api_key="your-api-key",
)
```

### 签名与验签消息

```python
msg = await agent.sign_message(
    payload={"ticket_id": "T-1001", "status": "triaged"},
    recipient="agent://agent.example.com/resolver",
    message_type="ticket.update",
)

result = await verify_agent_message(
    message=msg,
    nonce_store=nonce_store,
    http_client=http_client,
)
if not result.ok:
    raise PermissionError(f"{result.code}: {result.reason}")
```

## 运行测试

```powershell
cd D:\FDU\agent_auth\agent_auth_sdk
python -m pytest -q
```

当前验证结果：

```text
55 passed, 1 skipped
```

## 安全建议

- 生产环境使用 HTTPS Registry 和 HTTPS Vault
- 生产环境使用 `STRICT_PROFILE`
- 使用 `vault_token_file`，不要把 raw token 写进代码
- Vault Transit key 使用 `ecdsa-p256`
- Registry API key 应由 Registry 端以 PBKDF2-HMAC-SHA256 hash 保存
- 多实例部署时使用共享 nonce store，例如 Redis
- 不要在公开仓库提交真实 API key、Vault token 或生产 registry 凭证

## Changelog

### 1.0.0b1

- Agent metadata、Registry 发布与 owner 绑定
- Vault Transit ES256 签名
- HTTP 请求签名与验签
- 规范消息签名与验签
- timestamp + nonce 防重放
- STRICT/TEST runtime profile
- key rotation、add-key、revoke-key、revoke-agent
- OpenAI Agents SDK 显式轻量接入 CLI 与 runtime
