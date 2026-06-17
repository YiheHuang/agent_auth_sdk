# Agent Auth SDK

`agent-auth-sdk` 是一个 Python SDK，为多 Agent 系统提供从身份声明到跨 Agent 调用认证的最小可用协议。核心能力包括 Agent 身份创建、Registry 发布、HTTP 请求签名与验签、规范消息签名与验签，以及密钥安全轮换。

当前版本：`1.0.0b1`

## Quick Start

### 安装

```powershell
pip install -e .
```

### 创建 Agent（Vault Transit）

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
)
print(agent.agent_id)  # agent://agent.example.com/weather
```

### 签名 HTTP 请求

```python
signed = await agent.sign_http(method="POST", url="https://peer.example.com/tasks", body={"task": "hello"})
headers = signed.headers  # 附加到出站请求
```

### 验证 HTTP 请求

```python
from agent_auth_sdk import (
    FileMetadataCache,
    InMemoryNonceStore,
    MetadataResolverConfig,
    VerificationConfig,
    verify_http_request,
)

result = await verify_http_request(
    method="POST", url="...", headers=request_headers, body=request_body,
    nonce_store=InMemoryNonceStore(),
    cache=FileMetadataCache("runtime/metadata-cache.sqlite3"),
    http_client=http_client,
    resolver_config=MetadataResolverConfig(registry_url="https://registry.example.com/.well-known/agent.json"),
)
if not result.ok:
    raise PermissionError(f"{result.code}: {result.reason}")
```

---

## 六大核心接口

SDK 对开发者暴露 6 个接口类别，对应以下入口：

| # | 接口 | 入口 | 说明 |
|---|------|------|------|
| 1 | 创建 Agent Metadata | `AgentInstance.from_vault()` / `AgentInstance.from_signer()` | 从 Vault KMS 或自定义签名器创建 Agent 身份 |
| 2 | 发布到 Registry | `AgentInstance.publish()` | 将 metadata 发布到中心 Registry，含双重签名认证 |
| 3 | 签名消息 | `AgentInstance.sign_http()` / `AgentInstance.sign_message()` | HTTP 请求签名 / 规范消息签名 |
| 4 | 验签 | `verify_http_request()` / `verify_agent_message()` | HTTP 请求验签 / 消息验签（含 nonce 防重放） |
| 5 | 查询 Metadata | `resolve_agent()` | 从 Registry 或 `/.well-known/agent.json` 解析 metadata |
| 6 | 轮换密钥 | `AgentInstance.rotate_key()` | 双签名证明安全轮换 active key |

> 完整接口文档见 **[docs/API_REFERENCE.md](docs/API_REFERENCE.md)**。Vault 环境配置指南见 **[docs/VAULT_SETUP.md](docs/VAULT_SETUP.md)**。Registry `agent.json` 结构说明见 **[docs/REGISTRY_AGENT_JSON.md](docs/REGISTRY_AGENT_JSON.md)**。

### 签名与验签消息

```python
# 签名
msg = await agent.sign_message(
    payload={"ticket_id": "T-1001", "status": "triaged"},
    recipient="agent://agent.example.com/resolver",
    message_type="ticket.update",
)

# 验签
result = await verify_agent_message(message=msg, nonce_store=nonce_store, http_client=http_client)
```

### 轮换 Agent Key

```python
result = await agent.rotate_key(
    registry_url="https://registry.example.com/registry/agents/rotate-key",
    client_id="developer-a", api_key="your-api-key",
    new_signer=new_signer, new_public_key_pem=new_pem, new_kid="vault:transit/weather-agent-v2",
)
```

### 本地测试环境

```python
from agent_auth_sdk.config import TEST_PROFILE
from agent_auth_sdk import MetadataResolverConfig, VerificationConfig

config = MetadataResolverConfig(profile=TEST_PROFILE, registry_url="http://127.0.0.1:8008/.well-known/agent.json")
```

---

## Core Concepts

### Agent ID

格式：`agent://{host}/{name}`。`host` 用于定位 metadata well-known URL；strict profile 下要求 HTTPS 并拒绝 IP host。

### Metadata

单个 Agent 的 `/.well-known/agent.json` 包含身份、endpoint、capabilities、public keys、签名/验签策略。中心 Registry 的 `/.well-known/agent.json` 是聚合文档。

### Registry Publish

发布流程：(1) Agent key 签名 publish canonical string，(2) Registry 校验 developer API key，(3) 首次发布建立 `agent_id → developer_id` owner 绑定，(4) 后续发布必须同一 owner 且不能偷换 key。

### Key Rotation

必须走 `POST /registry/agents/rotate-key`。安全条件：developer API key 有效 + 旧 key 签名完整请求 + 新 key 签名 proof + timestamp 未过期 + nonce 不重放 + owner 匹配。

### Nonce & Timestamp

所有签名请求包含 timestamp 和 nonce：timestamp 拒绝过期请求，nonce 拒绝重放。生产多实例应使用共享 nonce store（如 Redis）。时序偏移由 profile 的 `clock_skew_seconds` 控制。

---

## Runtime Profiles

| Profile | HTTP | IP Host | 用途 |
|---------|------|---------|------|
| `STRICT_PROFILE`（默认） | 禁止 | 禁止 | 生产环境 |
| `TEST_PROFILE` | 允许 | 允许 | 本地测试与 demo |

---

## 常见验签错误码

| code | 含义 |
|------|------|
| `INVALID_AGENT_ID` | agent_id 格式无效 |
| `METADATA_FETCH_FAILED` | 无法获取或解析 metadata |
| `KEY_NOT_FOUND` / `KEY_REVOKED` / `KEY_EXPIRED` | 验签 key 不可用 |
| `SIGNATURE_INVALID` | 签名缺失或验签失败 |
| `TIMESTAMP_EXPIRED` | timestamp 超出允许偏移 |
| `NONCE_REPLAYED` | nonce 已使用（重放攻击） |
| `POLICY_REJECTED` | 当前 profile 或策略拒绝请求 |

---

## Security

- 使用 HTTPS registry 和 HTTPS Vault（生产）
- 使用 `STRICT_PROFILE`，不在公网使用 HTTP 或 IP host
- 使用 `vault_token_file`，不传 raw token
- Vault Transit key 使用 `ecdsa-p256`，私钥不可导出
- Registry API key 只保存 PBKDF2-HMAC-SHA256 hash
- 多实例部署使用共享 nonce store（如 Redis）

---

## Demo 项目

多 Agent 工单协作演示：**[agent_auth_demoproject](../agent_auth_demoproject)**，展示 4 个 Agent 完成签名、验签、攻击防御的完整流程。

## Changelog

### 1.0.0b1

首次 beta 版本：Agent metadata、Registry 发布与 owner 绑定、Vault Transit ES256 签名、HTTP 请求/规范消息的签名与验签、timestamp + nonce 防重放、STRICT/TEST profile、rotate-key 双签名证明。
