# Agent Auth SDK

`agent-auth-sdk` 是一个用于 Agent 身份发布、请求签名、消息签名和 registry 验签的 Python SDK。它面向多 Agent 系统，提供一套从身份声明到跨 Agent 调用认证的最小生产可用协议。

当前版本：`1.0.0b1`

## Quick Start

### 安装

开发安装：

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .[dev]
pytest -q
```

作为依赖安装：

```powershell
pip install agent-auth-sdk
```

如果包暂未发布到 PyPI，可以从本地路径安装：

```powershell
pip install -e C:\path\to\agent_auth_sdk
```

### 准备 Vault Transit

生产路径使用 HashiCorp Vault Transit 保存非导出私钥。SDK 不生成、不保存、不加载本地私钥，只读取 Vault Transit 公钥并调用 Transit 签名接口。

本地开发可以使用 Vault dev server：

```powershell
vault server -dev -dev-root-token-id=root
```

另开一个终端：

```powershell
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "root"
New-Item -ItemType Directory -Force runtime | Out-Null
Set-Content -Path runtime\vault-token.txt -Value "root"
vault secrets enable transit
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

生产环境推荐 Vault Agent sink token file 模式：由 Vault Agent、AppRole、OIDC 或平台身份系统续租短期 token，并写入本地文件；SDK 只读取 `vault_token_file`。

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
    environment="prod",
)

print(agent.agent_id)
# agent://agent.example.com/weather
```

### 导出 metadata

```python
agent.export_metadata("runtime")
```

输出文件：

```text
runtime/.well-known/agent.json
```

### 发布到 registry

```python
await agent.publish(
    registry_url="https://registry.example.com/registry/agents/publish",
    client_id="developer-a",
    api_key="your-developer-api-key",
)
```

当前演示环境如果仍使用 HTTP，需要显式使用 test/dev profile，并确认该路径只用于内网演示或本地验证。

### 签名 HTTP 请求

```python
signed = await agent.sign_http(
    method="POST",
    url="https://peer.example.com/tasks/handle",
    body={"task": "hello"},
)

headers = signed.headers
```

### 验证 HTTP 请求

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

## Examples

### 使用自定义 signer

`from_signer(...)` 适合接入 HSM、云 KMS 或测试 signer。自定义 signer 需要实现 `kid()`、`algorithm()` 和 `sign(data)`。

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.from_signer(
    domain="agent.example.com",
    name="publisher",
    organization="Example Lab",
    endpoint="https://agent.example.com/tasks/handle",
    signer=my_signer,
    public_key_pem=public_key_pem,
    kid="kms:publisher-key",
    capabilities=["publish", "sign"],
    environment="prod",
)
```

### 签名和验证规范消息

```python
signed_message = await agent.sign_message(
    payload={"ticket_id": "T-1001", "status": "triaged"},
    recipient="agent://agent.example.com/resolver",
    message_type="ticket.update",
)
```

接收方：

```python
from agent_auth_sdk import verify_agent_message

result = await verify_agent_message(
    message=signed_message,
    nonce_store=nonce_store,
    http_client=http_client,
    resolver_config=MetadataResolverConfig(
        registry_url="https://registry.example.com/.well-known/agent.json",
    ),
)
```

### 轮换 Agent key

普通 publish 禁止替换 `keys`。密钥轮换必须调用 `rotate-key`，并同时证明旧 active key 可控和新 key 私钥可控。

```python
result = await agent.rotate_key(
    registry_url="https://registry.example.com/registry/agents/rotate-key",
    client_id="developer-a",
    api_key="your-developer-api-key",
    new_signer=new_signer,
    new_public_key_pem=new_public_key_pem,
    new_kid="vault:transit/weather-agent-v2",
)
```

轮换成功后，registry 会把旧 key 标为 `inactive`，新 key 标为 `active`。

### 本地 test profile

默认配置使用 strict profile，不允许 HTTP 和 IP host。测试或本地 demo 可以显式使用 `TEST_PROFILE`：

```python
from agent_auth_sdk.config import MetadataResolverConfig, TEST_PROFILE, VerificationConfig

verification_config = VerificationConfig(profile=TEST_PROFILE)
resolver_config = MetadataResolverConfig(
    profile=TEST_PROFILE,
    registry_url="http://127.0.0.1:8008/.well-known/agent.json",
)
```

## API Reference

### High-level API

#### `AgentInstance.from_vault(...)`

生产推荐入口，从 Vault Transit 读取公钥并创建签名器。

关键参数：

| 参数 | 说明 |
| --- | --- |
| `domain` | Agent 所属域名，也是 `agent_id` 的 host 部分 |
| `name` | Agent 名称，也是 `agent_id` 的 path 部分 |
| `organization` | 组织名，写入 metadata |
| `endpoint` | Agent 服务入口 |
| `vault_addr` | Vault 地址 |
| `vault_token_file` | Vault token 文件路径，生产推荐且默认要求 |
| `transit_mount` | Transit mount path，默认常见值为 `transit` |
| `key_name` | Vault Transit key name |
| `capabilities` | Agent 能力声明 |
| `verify` | Vault TLS 校验，默认 `True` |
| `allow_insecure_raw_token` | 仅 dev/test 可设为 `True` |

#### `AgentInstance.from_signer(...)`

高级入口，用于自定义 signer、HSM、云 KMS 或测试。调用方必须提供 signer 与对应公钥。

#### `agent.export_metadata(output_dir)`

导出 `/.well-known/agent.json`。

#### `agent.publish(...)`

发布 metadata 到 registry。发布请求由当前 Agent key 签名，并携带 developer API key。

#### `agent.rotate_key(...)`

轮换 registry 中的 active key。请求包含旧 key 签名和新 key proof。

#### `agent.sign_http(...)`

为 HTTP 请求生成签名 headers。返回 `SignatureHeaders`，包含 `headers`、`canonical` 和 `body_digest`。

#### `agent.sign_message(...)`

生成 `SignedAgentMessage`。

### HTTP Signing API

| API | 说明 |
| --- | --- |
| `sign_http_request(...)` | 异步 HTTP 请求签名 |
| `sign_http_request_sync(...)` | 同步 HTTP 请求签名 |
| `verify_http_request(...)` | 异步 HTTP 请求验签 |
| `verify_http_request_sync(...)` | 同步 HTTP 请求验签 |

签名请求包含：

```text
x-agent-id
x-agent-kid
x-agent-timestamp
x-agent-nonce
x-agent-signature
x-agent-signature-input
host
```

### Message Signing API

| API | 说明 |
| --- | --- |
| `sign_agent_message(...)` | 异步规范消息签名 |
| `sign_agent_message_sync(...)` | 同步规范消息签名 |
| `verify_agent_message(...)` | 异步规范消息验签 |
| `verify_agent_message_sync(...)` | 同步规范消息验签 |
| `build_canonical_message(...)` | 构造规范消息签名串 |

### Metadata and Registry API

| API | 说明 |
| --- | --- |
| `render_agent_metadata(...)` | 构造 `AgentMetadata` |
| `export_well_known(...)` | 导出 well-known metadata |
| `publish_to_registry(...)` | 发布 metadata 到 registry |
| `rotate_key_in_registry(...)` | 执行显式密钥轮换 |
| `resolve_agent(...)` | 从 agent well-known 或中心 registry 解析 metadata |
| `select_verification_key(...)` | 从 metadata 中选择 active 验签 key |

### Vault KMS API

| API | 说明 |
| --- | --- |
| `VaultKmsConfig` | Vault Transit 配置 |
| `VaultTransitSigner` | Vault Transit ES256 signer |
| `VaultTransitPublicKeyResolver` | Vault Transit 公钥解析器 |
| `resolve_vault_public_key(...)` | 读取 Transit 公钥 |
| `validate_vault_key(...)` | 校验公钥读取和签名权限 |

### Stores

| API | 说明 |
| --- | --- |
| `InMemoryNonceStore` | 内存 nonce store，适合测试或单进程 demo |
| `RedisNonceStore` | Redis nonce store，适合多实例部署 |
| `InMemoryMetadataCache` | 内存 metadata cache |
| `FileMetadataCache` | SQLite 文件 metadata cache |

### Models

常用模型：

| 模型 | 说明 |
| --- | --- |
| `AgentMetadata` | 单个 Agent 的身份 metadata |
| `AgentKey` | Agent 公钥声明 |
| `AgentRegistryDocument` | registry 聚合文档 |
| `SignedAgentMessage` | 已签名规范消息 |
| `SignatureHeaders` | HTTP 签名结果 |
| `VerificationSuccess` | 验签成功结果 |
| `VerificationFailure` | 验签失败结果 |

## Core Concepts

### Agent ID

Agent ID 使用：

```text
agent://<host>/<name>
```

示例：

```text
agent://agent.example.com/weather
```

`host` 用来定位 metadata。strict profile 下要求 HTTPS metadata 解析，并拒绝 IP host；test profile 允许 HTTP 和 IP host。

### Metadata

单个 Agent 的 `/.well-known/agent.json` 包含身份、endpoint、capabilities、public keys、签名策略、验签策略和审计配置。

中心 registry 的 `/.well-known/agent.json` 是聚合文档，包含多个 Agent 的 metadata。

### Registry Publish

发布流程：

1. SDK 从 Vault Transit 或自定义 signer 获取签名能力。
2. SDK 构造 publish payload。
3. Agent key 对 publish canonical string 签名。
4. Registry 校验 developer API key。
5. Registry 使用 metadata 中的公钥验证 Agent 签名。
6. 首次发布建立 `agent_id -> developer_id` owner 绑定。
7. 后续发布必须来自同一 owner，且不能偷偷替换 key。

### Key Rotation

密钥轮换必须走：

```text
POST /registry/agents/rotate-key
```

安全条件：

1. developer API key 必须有效。
2. 旧 active key 必须对完整 rotate 请求签名。
3. 新 key 必须对绑定 `agent_id`、`new_key.kid`、新公钥指纹、timestamp、nonce、client_id 和 host 的 canonical proof 签名。
4. proof timestamp 必须在允许时间窗内。
5. proof nonce 不能重放。
6. owner 必须匹配。

任一条件失败，registry 拒绝轮换。

### Nonce and Timestamp

所有请求和消息签名都包含 timestamp 与 nonce：

| 字段 | 用途 |
| --- | --- |
| timestamp | 拒绝过期请求 |
| nonce | 拒绝重放请求 |

生产多实例部署应使用共享 nonce store，例如 Redis。

### Runtime Profiles

| Profile | HTTP | IP host | 默认用途 |
| --- | --- | --- | --- |
| `STRICT_PROFILE` | 不允许 | 不允许 | 生产默认 |
| `TEST_PROFILE` | 允许 | 允许 | 本地测试和 demo |

SDK 默认使用 `STRICT_PROFILE`。本地 HTTP demo 必须显式传入 `TEST_PROFILE`。

## Errors

### Verification errors

`verify_http_request(...)` 和 `verify_agent_message(...)` 返回 `VerificationSuccess` 或 `VerificationFailure`，不会把常规验签失败当成异常抛出。

| code | 含义 |
| --- | --- |
| `INVALID_AGENT_ID` | `agent_id` 格式无效 |
| `INVALID_METADATA` | metadata 不合法 |
| `METADATA_FETCH_FAILED` | 无法获取或解析 metadata |
| `METADATA_HOST_MISMATCH` | metadata host 与身份不匹配 |
| `KEY_NOT_FOUND` | 找不到指定 active key |
| `KEY_REVOKED` | key 已撤销 |
| `KEY_EXPIRED` | key 已过期 |
| `SIGNATURE_INVALID` | 签名缺失、格式错误或验签失败 |
| `TIMESTAMP_EXPIRED` | timestamp 无效或超出允许偏移 |
| `NONCE_REPLAYED` | nonce 已使用 |
| `POLICY_REJECTED` | 当前 profile 或策略拒绝请求 |

示例：

```python
result = await verify_http_request(...)
if not result.ok:
    logger.warning("auth rejected: %s %s", result.code, result.reason)
```

### Exceptions

| 异常 | 场景 |
| --- | --- |
| `AgentIdentityError` | Agent ID 格式错误或 host/name 缺失 |
| `MetadataValidationError` | metadata 内容不符合 profile 或协议要求 |
| `ValueError` | 配置缺失、Vault key 类型不支持、token 文件不可读等 |
| `httpx.HTTPStatusError` | publish、rotate-key 或 registry 请求返回非 2xx |

### Registry rejection codes

Registry 的 HTTP 错误通常位于响应 body 的 `detail` 字段。常见值：

| detail | 含义 |
| --- | --- |
| `INVALID_API_KEY` | developer API key 无效 |
| `UNKNOWN_CLIENT` | client id 不存在或已吊销 |
| `SIGNATURE_INVALID` | publish 或 rotate 请求签名无效 |
| `INVALID_TIMESTAMP` | 请求 timestamp 格式无效 |
| `TIMESTAMP_EXPIRED` | 请求 timestamp 过期 |
| `NONCE_REPLAYED` | nonce 重放 |
| `OWNER_MISMATCH` | 尝试更新不属于当前 developer 的 Agent |
| `KEY_CHANGE_REQUIRES_ROTATION` | 普通 publish 试图替换 key |
| `NEW_KEY_PROOF_REQUIRED` | rotate-key 缺少新 key proof |
| `NEW_KEY_PROOF_INVALID` | 新 key proof 无效 |

## Config

### VaultKmsConfig

```python
from agent_auth_sdk import VaultKmsConfig

config = VaultKmsConfig(
    vault_addr="https://vault.example.com",
    vault_token_file="/run/secrets/vault-token",
    transit_mount="transit",
    key_name="weather-agent",
    verify=True,
)
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `vault_addr` | 必填 | Vault 地址 |
| `transit_mount` | 必填 | Transit mount |
| `key_name` | 必填 | Transit key name |
| `vault_token_file` | `None` | 生产推荐 token 文件 |
| `vault_token` | `None` | dev/test-only raw token |
| `namespace` | `None` | Vault Enterprise namespace |
| `verify` | `True` | TLS 校验，支持 bool 或 CA 文件路径 |
| `kid` | `None` | 自定义 key id |
| `allow_insecure_raw_token` | `False` | 显式开启 dev/test raw token 和跳过 TLS 校验能力 |

生产默认拒绝：

```python
VaultKmsConfig(
    vault_addr="https://vault.example.com",
    transit_mount="transit",
    key_name="weather-agent",
    vault_token="raw-token",
)
# ValueError: Raw vault_token is dev/test-only. Use vault_token_file in production.
```

本地开发如确需 raw token：

```python
VaultKmsConfig(
    vault_addr="http://127.0.0.1:8200",
    transit_mount="transit",
    key_name="weather-agent",
    vault_token="root",
    allow_insecure_raw_token=True,
    verify=True,
)
```

### VerificationConfig

```python
from agent_auth_sdk import VerificationConfig

config = VerificationConfig()
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `profile` | `STRICT_PROFILE` | 验签安全策略 |
| `require_signature_input_header` | `True` | 是否要求 `x-agent-signature-input` |

### SigningConfig

```python
from agent_auth_sdk import SigningConfig

config = SigningConfig()
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `profile` | `STRICT_PROFILE` | 签名安全策略 |
| `include_signature_input_header` | `True` | 是否写入 `x-agent-signature-input` |

### MetadataResolverConfig

```python
from agent_auth_sdk import MetadataResolverConfig

config = MetadataResolverConfig(
    registry_url="https://registry.example.com/.well-known/agent.json",
)
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `profile` | `STRICT_PROFILE` | metadata 解析安全策略 |
| `cache_ttl_seconds` | `None` | 覆盖 profile 中的缓存 TTL |
| `request_timeout_seconds` | `10.0` | metadata 请求超时 |
| `registry_url` | `None` | 中心 registry 聚合文档地址 |

### Registry environment

本地 registry 服务读取环境变量：

| 变量 | 说明 |
| --- | --- |
| `AGENT_REGISTRY_DB_PATH` | SQLite 数据库路径 |
| `AGENT_REGISTRY_PATH` | 公开 `.well-known/agent.json` 输出路径 |
| `AGENT_REGISTRY_PORT` | 服务端口 |
| `AGENT_REGISTRY_ALLOWED_SKEW_SECONDS` | publish/rotate timestamp 允许偏移 |

启动：

```powershell
$env:AGENT_REGISTRY_DB_PATH = "runtime\registry\registry.sqlite3"
$env:AGENT_REGISTRY_PATH = "runtime\registry\.well-known\agent.json"
$env:AGENT_REGISTRY_PORT = "8008"
agent-auth-registry
```

管理 CLI：

```powershell
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin list-developers
agent-auth-registry-admin revoke-developer --client-id developer-a
agent-auth-registry-admin inspect-agent --agent-id agent://agent.example.com/weather
```

## Changelog

### 1.0.0b1

首次 beta 版本，包含：

- Agent metadata 构造与 `/.well-known/agent.json` 导出。
- 中心 registry 发布、owner 绑定和聚合发现。
- Vault Transit `ecdsa-p256` ES256 签名支持。
- HTTP 请求签名和验签。
- `SignedAgentMessage` 规范消息签名和验签。
- timestamp 与 nonce 防重放。
- `STRICT_PROFILE` 和 `TEST_PROFILE`。
- `vault_token_file` 生产入口。
- raw `vault_token` dev/test-only 防护。
- `rotate-key` 双签名证明。
- developer API key PBKDF2 hash 存储，兼容旧 SHA-256 hash 迁移。

## Security

### Production requirements

生产或准生产部署至少满足：

1. 使用 HTTPS registry 和 HTTPS Vault。
2. 使用 `STRICT_PROFILE`，不要在公网生产验收路径使用 HTTP 或 IP host。
3. 使用 `vault_token_file`，不要通过环境变量或源码传 raw Vault token。
4. 使用 Vault Agent sink、AppRole、OIDC 或平台身份生成短期 token。
5. Vault Transit key 使用 `ecdsa-p256`，私钥不可导出。
6. Agent Vault policy 只授予 `read transit/keys/<key>` 和 `update transit/sign/<key>`。
7. Registry developer API key 只保存带随机 salt 的 PBKDF2-HMAC-SHA256 hash。
8. 多实例部署使用共享 nonce store。
9. 备份 registry SQLite 数据库，并保护 developer/owner 绑定数据。

### Vault policy example

```hcl
path "transit/keys/weather-agent" {
  capabilities = ["read"]
}

path "transit/sign/weather-agent" {
  capabilities = ["update"]
}
```

### Insecure dev-only switches

以下能力只允许本地开发和测试：

| 能力 | 开启方式 | 风险 |
| --- | --- | --- |
| raw Vault token | `allow_insecure_raw_token=True` | token 容易泄露到环境变量、日志或进程列表 |
| 跳过 Vault TLS 校验 | `verify=False` 且 `allow_insecure_raw_token=True` | 可能遭遇中间人攻击 |
| HTTP metadata/registry | `TEST_PROFILE` | 传输链路无机密性和完整性保护 |
| IP host agent id | `TEST_PROFILE` | 不适合公网身份绑定 |

### Threat model

SDK 和 registry 主要防护：

| 攻击 | 防护 |
| --- | --- |
| 只盗取 registry API key | publish 仍需 Agent key 签名 |
| owner 冲突发布 | registry 使用 `agent_id -> developer_id` 绑定拒绝 |
| 普通 publish 偷换 key | 返回 `KEY_CHANGE_REQUIRES_ROTATION` |
| rotate-key 未持有旧 key | 旧 active key 签名校验失败 |
| rotate-key 未持有新 key | 新 key proof 校验失败 |
| 请求重放 | timestamp + nonce store |
| metadata 篡改 | 签名验签失败或 key/host 校验失败 |

暂不覆盖：

| 范围 | 说明 |
| --- | --- |
| Vault 运维安全 | 解封、审计、HA、备份和 root token 管理由部署方负责 |
| WAF/rate limit | 需要在网关或部署层补齐 |
| 完整 PKI 治理 | 当前依赖 HTTPS 与 registry owner 绑定 |
| 云 KMS 官方适配 | 可通过 `from_signer(...)` 扩展 |

## Testing

运行 SDK 测试：

```powershell
pytest -q
```

真实 Vault 集成测试：

```powershell
$env:AGENT_AUTH_TEST_VAULT_ADDR = "http://127.0.0.1:8200"
$env:AGENT_AUTH_TEST_VAULT_TOKEN_FILE = "runtime\vault-token.txt"
$env:AGENT_AUTH_TEST_VAULT_TRANSIT_MOUNT = "transit"
$env:AGENT_AUTH_TEST_VAULT_KEY_NAME = "weather-agent"
pytest -q
```

未配置真实 Vault 时，相关集成测试会 `skip`，不会回退到本地私钥。

## Demo Project

多 Agent 工单协作演示项目位于：

```text
../agent_auth_demoproject
```

Demo 展示：

- 4 个独立 Agent 自动发布 metadata。
- 正常工单在多个 Agent 间流转。
- 每一步跨 Agent 调用都经过签名与验签。
- 未注册 Agent、签名篡改、nonce 重放、盗取 registry API key、owner 冲突等攻击被拒绝。
- 攻击结果展示在工单详情时间线和认证事件面板。

## Deployment

CentOS / OpenCloudOS 部署说明见：

[deploy/DEPLOY_BETA_V1.md](deploy/DEPLOY_BETA_V1.md)

当前演示部署可使用 HTTP；生产公网部署建议统一升级到 HTTPS，并按 Security 章节收紧配置。
