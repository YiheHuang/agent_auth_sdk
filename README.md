# Agent Auth SDK

`agent-auth-sdk` 是一个面向多 Agent 系统的 Python SDK，用来解决三个核心问题：

- Agent 如何发布自己的可信身份信息。
- Agent 如何发送带签名的规范消息或 HTTP 请求。
- 接收方如何从中心 registry 发现 Agent 公钥并验证发送方身份。

当前 beta-v1 的正式安全路径是 **HashiCorp Vault Transit**。正式主路径不生成、不保存、不加载本地私钥；开发者需要自行部署和管理 Vault，SDK 只调用 Vault Transit 的 `read_key` 与 `sign_data` 能力。

## 安全模型

beta-v1 的安全边界由三部分组成：

- **开发者身份认证**：registry 发布接口要求 `client_id + developer api key`。
- **Agent 持钥证明**：发布 metadata、发送 HTTP 请求、发送消息时，都必须由 Agent 对应的 Vault Transit key 完成签名。
- **Registry owner 绑定**：首次发布会建立 `agent_id -> developer_id` 绑定，后续只有同一个 owner 才能更新该 Agent。

这意味着仅泄露 registry API key 不能覆盖别人的 Agent metadata；攻击者还必须同时拥有对应 Agent 的 Vault Transit 签名权限。

## 核心特性

- `agent://host/name` 格式的稳定 `agent_id`。
- HashiCorp Vault Transit `ecdsa-p256` 非导出私钥签名。
- 对外统一使用 `ES256` 算法标识。
- `/.well-known/agent.json` metadata 导出与中心 registry 聚合发现。
- `POST /registry/agents/publish` 安全发布。
- `POST /registry/agents/rotate-key` 显式密钥轮换。
- HTTP 请求签名与验签。
- `SignedAgentMessage` 规范消息签名与验签。
- timestamp 与 nonce 防重放。
- metadata 缓存与 nonce store 抽象。
- 本地 registry 服务与 registry 管理 CLI。

## 安装

开发安装：

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
```

发布到包索引后，作为依赖安装：

```bash
pip install agent-auth-sdk
```

如果项目暂不发布到 PyPI，也可以从本地路径或 Git 仓库安装：

```bash
pip install -e C:\path\to\agent_auth_sdk
```

## 角色边界

`agent-auth-sdk` 只负责协议与 SDK 能力，不托管开发者基础设施。

开发者需要自己负责：

- 安装、初始化、解封 HashiCorp Vault。
- 启用 Transit Secrets Engine。
- 创建 `ecdsa-p256` Transit key。
- 配置 Vault policy 与 token。
- 保护 Vault token、Vault 存储、备份和高可用。

SDK 负责：

- 从 Vault Transit 读取公钥。
- 调用 Vault Transit 完成签名。
- 生成 Agent metadata。
- 发布 metadata 到 registry。
- 构造 HTTP 或消息签名。
- 根据 registry metadata 完成验签。

Registry 不需要 Vault token，也不需要访问 Vault；它只消费 metadata 中的公钥。

## Vault Transit 配置

### 本地开发模式

本地演示可以使用 Vault dev server：

```bash
vault server -dev -dev-root-token-id=root
```

另开一个终端：

```bash
set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=root
vault secrets enable transit
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

dev root token 只适合本地开发和演示，不要用于生产或准生产环境。

### 准生产最小 Policy

Agent 运行时只需要读取公钥和发起签名，建议使用独立 token，并限制权限：

```hcl
path "transit/keys/weather-agent" {
  capabilities = ["read"]
}

path "transit/sign/weather-agent" {
  capabilities = ["update"]
}
```

如果一个服务管理多个 Agent key，可以按 key name 分别配置 policy，不建议直接给 root token。

### SDK 所需 Vault 参数

| 参数 | 说明 |
| --- | --- |
| `vault_addr` | Vault 地址，例如 `http://127.0.0.1:8200` |
| `vault_token` | 具有 `read` 和 `sign` 权限的 Vault token |
| `transit_mount` | Transit mount path，默认 `transit` |
| `key_name` | Vault Transit key name |
| `namespace` | Vault Enterprise namespace，可选 |
| `verify` | TLS 校验设置，默认 `True`，也可传 CA 文件路径 |
| `kid` | metadata 中的 key id，可选，默认 `vault:<mount>/<key_name>` |

beta-v1 固定要求：

- Vault key type：`ecdsa-p256`
- Vault sign hash：`sha2-256`
- Vault ECDSA marshaling：`asn1`
- SDK alg：`ES256`

## 最小 SDK 用法

创建 Agent 实例并导出 metadata：

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.from_vault(
    domain="agent.example.com",
    name="weather",
    organization="Example Lab",
    endpoint="https://agent.example.com/tasks/handle",
    vault_addr="http://127.0.0.1:8200",
    vault_token="root",
    transit_mount="transit",
    key_name="weather-agent",
    capabilities=["weather.query", "sign", "verify"],
    environment="beta",
)

agent.export_metadata("runtime")
```

导出的文件位置：

```text
runtime/.well-known/agent.json
```

发布到中心 registry：

```python
await agent.publish(
    registry_url="https://registry.example.com/registry/agents/publish",
    client_id="developer-a",
    api_key="your-developer-api-key",
)
```

发送签名 HTTP 请求：

```python
signed = await agent.sign_http(
    method="POST",
    url="https://peer.example.com/tasks/handle",
    body={"task": "hello"},
)

# signed.headers 需要随真实 HTTP 请求一起发送
```

接收方验签：

```python
import httpx
from agent_auth_sdk import (
    FileMetadataCache,
    InMemoryNonceStore,
    MetadataResolverConfig,
    verify_http_request,
)

nonce_store = InMemoryNonceStore()
cache = FileMetadataCache("runtime/metadata-cache.sqlite3")

async with httpx.AsyncClient() as client:
    result = await verify_http_request(
        method="POST",
        url="https://peer.example.com/tasks/handle",
        headers=request_headers,
        body=request_body,
        nonce_store=nonce_store,
        http_client=client,
        cache=cache,
        resolver_config=MetadataResolverConfig(
            registry_url="https://registry.example.com/.well-known/agent.json",
        ),
    )

if not result.ok:
    raise PermissionError(f"{result.code}: {result.reason}")
```

## 核心接口

### Agent 构造

- `AgentInstance.from_vault(...)`：正式推荐入口，从 Vault Transit 读取公钥并创建 Vault signer。
- `AgentInstance.from_signer(...)`：高级扩展入口，可接入自定义 signer、HSM 或远程签名服务。

### Vault KMS

- `VaultKmsConfig`
- `VaultTransitSigner`
- `VaultTransitPublicKeyResolver`
- `validate_vault_key(...)`

### Metadata 与 Registry

- `render_agent_metadata(...)`
- `export_well_known(...)`
- `publish_to_registry(...)`
- `resolve_agent(...)`

### HTTP 签名

- `sign_http_request(...)`
- `sign_http_request_sync(...)`
- `verify_http_request(...)`
- `verify_http_request_sync(...)`

签名请求会包含以下 headers：

```text
x-agent-id
x-agent-kid
x-agent-timestamp
x-agent-nonce
x-agent-signature
x-agent-signature-input
host
```

### 规范消息

- `sign_agent_message(...)`
- `verify_agent_message(...)`
- `sign_agent_message_sync(...)`
- `verify_agent_message_sync(...)`

## 核心流程

### 1. 开发者准备 Vault

1. 部署并解封 Vault。
2. 启用 Transit Secrets Engine。
3. 创建 `ecdsa-p256` key。
4. 为 Agent 创建最小权限 token。
5. 将 `VAULT_ADDR`、`VAULT_TOKEN`、Transit mount 和 key name 提供给 Agent 运行环境。

### 2. Registry 管理员创建开发者凭证

```bash
agent-auth-registry-admin create-developer --client-id developer-a
```

命令会输出一次性 API key。请妥善保存原始 key；registry 只保存 hash，无法反查原文。

### 3. Agent 发布 metadata

1. SDK 从 Vault 读取公钥，生成 `AgentMetadata`。
2. SDK 构造 `POST /registry/agents/publish` 请求。
3. SDK 用 Vault Transit key 对发布 canonical string 签名。
4. Registry 校验 developer API key。
5. Registry 用 metadata 里的公钥验证 Agent 签名。
6. 首次发布建立 owner 绑定；后续更新必须由同 owner 和当前 active key 完成。
7. Registry 写入 SQLite，并刷新公开 `/.well-known/agent.json`。

### 4. Agent 间 HTTP 调用

1. 发送方对 method、path、body digest、agent_id、kid、timestamp、nonce、host 构造 canonical string。
2. 发送方调用 Vault Transit 签名。
3. 接收方从 `x-agent-id` 得到发送方身份。
4. 接收方通过 registry 解析发送方 metadata。
5. 接收方选择 `kid` 对应的 active 公钥验签。
6. 接收方检查 timestamp 与 nonce，防止过期请求和重放。

### 5. 密钥轮换

普通 publish 不允许偷偷替换 `keys`。轮换必须使用：

```text
POST /registry/agents/rotate-key
```

轮换规则：

- 请求由当前 active key 签名。
- 请求体提交新 key 的公钥材料。
- Registry 验签通过后把旧 key 标为 `inactive`，新 key 标为 `active`。
- 后续 publish 必须使用新 active key。

## Registry 服务

### 启动本地 Registry

```bash
set AGENT_REGISTRY_DB_PATH=runtime/registry/registry.sqlite3
set AGENT_REGISTRY_PATH=runtime/registry/.well-known/agent.json
set AGENT_REGISTRY_PORT=8008
agent-auth-registry
```

Registry 接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康检查 |
| `GET` | `/.well-known/agent.json` | 公开 Agent registry 文档 |
| `POST` | `/registry/agents/publish` | 安全发布或更新 metadata |
| `POST` | `/registry/agents/rotate-key` | 显式密钥轮换 |

### Registry 管理 CLI

创建开发者：

```bash
agent-auth-registry-admin create-developer --client-id developer-a
```

列出开发者：

```bash
agent-auth-registry-admin list-developers
```

吊销开发者：

```bash
agent-auth-registry-admin revoke-developer --client-id developer-a
```

查看 Agent owner 绑定：

```bash
agent-auth-registry-admin inspect-agent --agent-id agent://agent.example.com/weather
```

## Metadata 结构

单个 Agent 的 `/.well-known/agent.json` 主要字段如下：

```json
{
  "version": "1.0",
  "agent_id": "agent://agent.example.com/weather",
  "domain": "agent.example.com",
  "name": "weather",
  "organization": "Example Lab",
  "endpoint": "https://agent.example.com/tasks/handle",
  "capabilities": ["weather.query", "sign", "verify"],
  "keys": [
    {
      "kid": "vault:transit/weather-agent",
      "alg": "ES256",
      "status": "active",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----..."
    }
  ],
  "updated_at": "2026-06-16T00:00:00Z",
  "environment": "beta"
}
```

中心 registry 的 `/.well-known/agent.json` 是聚合文档：

```json
{
  "version": "1.0",
  "registry_type": "agent_registry",
  "updated_at": "2026-06-16T00:00:00Z",
  "agents": [
    {
      "agent_id": "agent://agent.example.com/weather",
      "metadata": {},
      "published_at": "2026-06-16T00:00:00Z"
    }
  ]
}
```

## 错误码与拒绝场景

常见拒绝原因：

| 错误码 | 含义 |
| --- | --- |
| `METADATA_FETCH_FAILED` | 无法从 registry 获取发送方 metadata |
| `SIGNATURE_INVALID` | 签名无效或请求内容被篡改 |
| `NONCE_REPLAYED` | nonce 已使用，请求被判定为重放 |
| `TIMESTAMP_EXPIRED` | 请求时间戳超出允许偏移 |
| `KEY_NOT_FOUND` | metadata 中找不到指定 active `kid` |
| `KEY_REVOKED` | key 已被撤销 |
| `KEY_EXPIRED` | key 已过期 |
| `OWNER_MISMATCH` | 尝试更新不属于当前 developer 的 Agent |
| `KEY_CHANGE_REQUIRES_ROTATION` | 普通 publish 试图替换 key，必须走 rotate-key |

## 测试

运行本地测试：

```bash
pytest
```

真实 Vault 集成测试需要配置：

```bash
set AGENT_AUTH_TEST_VAULT_ADDR=http://127.0.0.1:8200
set AGENT_AUTH_TEST_VAULT_TOKEN=root
set AGENT_AUTH_TEST_VAULT_TRANSIT_MOUNT=transit
set AGENT_AUTH_TEST_VAULT_KEY_NAME=weather-agent
pytest
```

未配置真实 Vault 时，相关集成测试会显式 `skip`，不会回退到本地私钥。

## Demo Project

多 Agent 工单协作演示项目位于相邻目录：

```text
agent_auth_demoproject
```

Demo 展示：

- 4 个独立 Agent 自动发布 metadata。
- 正常工单在多个 Agent 间流转。
- 每一步跨 Agent 调用都经过签名与验签。
- 未注册 Agent、签名篡改、nonce 重放、盗取 registry API key、owner 冲突等攻击被拒绝。

Demo 也需要开发者提供 Vault 配置与 registry developer 凭证。

## 部署

CentOS / OpenCloudOS 部署说明见：

[deploy/DEPLOY_BETA_V1.md](deploy/DEPLOY_BETA_V1.md)

生产或准生产部署时请至少注意：

- Registry SQLite 数据库需要备份。
- Registry API key 泄露后应立即吊销并重新创建 developer。
- Vault token 不要写入代码仓库。
- Vault dev server 只用于本地演示。
- Agent 服务和 registry 建议统一使用 HTTPS。
- 各 Agent 应使用最小权限 Vault policy。

## 当前限制

- beta-v1 正式路径只支持 HashiCorp Vault Transit。
- beta-v1 正式 key type 只支持 `ecdsa-p256`。
- SDK 不提供本地私钥 fallback。
- Registry 当前使用 SQLite 作为权威存储，适合 beta 和轻量部署。
- `from_signer(...)` 可扩展到其他 KMS/HSM，但需要开发者自己实现 signer。
