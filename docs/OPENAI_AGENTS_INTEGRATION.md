# OpenAI Agents SDK 轻量接入指南

本文档说明如何把已有 OpenAI Agents SDK 多 Agent 项目接入 `agent-auth-sdk`。当前推荐方式是**少量显式代码改动**，不使用 monkey patch，也不追求零源码改动。

## 设计目标

- 保留 OpenAI Agents SDK 的 `Agent`、`function_tool`、`Runner.run` 编排方式
- 只在跨 Agent tool 调用边界加入认证
- SDK 负责 Vault key、Registry metadata、签名、验签、nonce 防重放、recipient 校验和 capability 校验
- 开发者能够清楚看到每个认证边界，不依赖隐藏 patch

## 原始调用与接入后调用

原始代码通常是：

```python
@function_tool
async def run_security_review(payload: dict) -> dict:
    return await Runner.run(security, payload)
```

接入后改为：

```python
@function_tool
async def run_security_review(payload: dict) -> dict:
    auth = await get_auth_adapter()
    return await auth.call_agent(
        source_role="coordinator",
        target_role="security",
        target_agent=security,
        payload=payload,
        runner=Runner.run,
    )
```

这就是核心改动。`Runner.run` 仍由 OpenAI Agents SDK 执行，SDK 只是包住这次跨 Agent 调用。

## `auth.call_agent(...)` 做了什么

从开发者视角看：

```text
coordinator -> auth.call_agent(...) -> Runner.run(security, payload) -> verified result
```

SDK 内部会执行：

1. source role 对请求 payload 签名
2. target role 验证请求签名、recipient、capability、timestamp、nonce
3. 调用传入的 `runner(target_agent, payload)`
4. target role 对结果 payload 签名
5. source role 验证结果签名、recipient、capability、timestamp、nonce
6. 记录 trusted event，例如 `coordinator -> security -> coordinator verified`

开发者不需要手写这些协议细节。

## CLI

命令：

```powershell
agent-auth integrate-openai-agents `
  --project-root . `
  --roles coordinator,security,architecture `
  --mode vault `
  --domain 127.0.0.1:8711 `
  --organization "Agent Auth App" `
  --registry-url http://registry.example.com/.well-known/agent.json `
  --registry-publish-url http://registry.example.com/registry/agents/publish `
  --role-capability coordinator:review.coordinate `
  --role-capability security:review.security `
  --role-capability architecture:review.architecture
```

生成文件：

| 文件 | 作用 |
|---|---|
| `.agent-auth/agent-auth.toml` | SDK runtime 配置：roles、domain、capabilities、registry、vault |
| `.agent-auth/auth_adapter.py` | 薄 adapter，加载 SDK 集成层 |
| `.agent-auth/env.local.example` | local 模式环境模板 |
| `.agent-auth/env.vault.example` | vault 模式环境模板 |
| `.agent-auth/INTEGRATION_REPORT.md` | CLI 自动生成的接入提示 |

CLI 不修改业务源码。业务源码改动由开发者显式完成。

## 配置文件

`agent-auth.toml` 示例：

```toml
mode = "vault"
domain = "127.0.0.1:8711"
organization = "Agent Auth Simple Original"
environment = "local"
profile = "test"
runtime_dir = "runtime"
roles = ["coordinator", "security", "architecture"]

[capabilities]
coordinator = "review.coordinate"
security = "review.security"
architecture = "review.architecture"

[registry]
url = "http://192.144.228.237/.well-known/agent.json"
publish_url = "http://192.144.228.237/registry/agents/publish"
client_id = "${AGENT_AUTH_REGISTRY_CLIENT_ID}"
api_key = "${AGENT_AUTH_REGISTRY_API_KEY}"

[vault]
addr = "${AGENT_AUTH_VAULT_ADDR}"
token_file = "${AGENT_AUTH_VAULT_TOKEN_FILE}"
transit_mount = "${AGENT_AUTH_VAULT_TRANSIT_MOUNT}"
auto_create_keys = true

[vault.key_names]
coordinator = "${AGENT_AUTH_COORDINATOR_KEY_NAME}"
security = "${AGENT_AUTH_SECURITY_KEY_NAME}"
architecture = "${AGENT_AUTH_ARCHITECTURE_KEY_NAME}"
```

## 环境变量

真实 Vault/Registry 模式示例：

```powershell
$env:AGENT_AUTH_ENABLED = "1"
$env:AGENT_AUTH_MODE = "vault"

$env:AGENT_AUTH_REGISTRY_CLIENT_ID = "your-client-id"
$env:AGENT_AUTH_REGISTRY_API_KEY = "your-api-key"

$env:AGENT_AUTH_VAULT_ADDR = "http://127.0.0.1:8300"
$env:AGENT_AUTH_VAULT_TOKEN_FILE = "D:\path\to\vault-token.txt"
$env:AGENT_AUTH_VAULT_TRANSIT_MOUNT = "transit"

$env:AGENT_AUTH_COORDINATOR_KEY_NAME = "simple-original-coordinator"
$env:AGENT_AUTH_SECURITY_KEY_NAME = "simple-original-security"
$env:AGENT_AUTH_ARCHITECTURE_KEY_NAME = "simple-original-architecture"
```

禁用认证但保留业务流程：

```powershell
$env:AGENT_AUTH_ENABLED = "0"
```

此时 `auth.call_agent(...)` 会直接调用原始 `runner(target_agent, payload)`。

## 集成层 API

### `OpenAIAgentsAuthConfig`

读取 `.agent-auth/agent-auth.toml`：

```python
from agent_auth_sdk.integrations.openai_agents import OpenAIAgentsAuthConfig

config = OpenAIAgentsAuthConfig.from_file(".agent-auth/agent-auth.toml")
```

### `AuthenticatedOpenAIAgents`

创建认证 adapter：

```python
from agent_auth_sdk.integrations.openai_agents import AuthenticatedOpenAIAgents

auth = await AuthenticatedOpenAIAgents.from_config_file(".agent-auth/agent-auth.toml")
```

调用 Agent：

```python
result = await auth.call_agent(
    source_role="coordinator",
    target_role="security",
    target_agent=security,
    payload=payload,
    runner=Runner.run,
)
```

查看可信事件：

```python
events = auth.trusted_events()
```

### `wrap_tool(...)`

如果希望提前生成 tool callable：

```python
run_security_review = auth.wrap_tool(
    source_role="coordinator",
    target_role="security",
    target_agent=security,
    runner=Runner.run,
)
```

## 模式

### local

`mode = "local"` 使用内存 ES256 signer 和 mock registry，适合单元测试和离线 demo。

### vault

`mode = "vault"` 使用 Vault Transit 创建/读取 key，并发布 metadata 到真实 registry。

首次运行时，如果 `auto_create_keys = true`，SDK 会自动创建 `ecdsa-p256` Transit key。

## Demo 对照

参考 [agent_auth_demo_simple_integration](../../agent_auth_demo_simple_integration)：

- `original_project`: coordinator 调用 security / architecture
- `pipeline_project`: intake -> classifier -> resolver -> summarizer
- `peer_collaboration_project`: researcher / critic / editor peer collaboration

每个项目都包含：

- `.agent-auth/agent-auth.toml`
- `.agent-auth/env.vault.ps1`
- `agent_auth_loader.py`
- `AGENT_AUTH_INTEGRATION_REPORT.md`

`original_project` 还包含接入前/接入后的 PlantUML 和 SVG 图。

## 设计取舍

当前实现不提供 runtime shim 或 monkey patch。原因是：

- 显式边界更稳定
- 开发者能清楚审查每个跨 Agent 信任边界
- 不依赖 OpenAI Agents SDK 私有实现
- 项目升级 OpenAI Agents SDK 时更不容易被隐藏 patch 影响

推荐原则：凡是一个 Agent 通过 tool 调另一个 Agent，就用 `auth.call_agent(...)` 包住这一处边界。
