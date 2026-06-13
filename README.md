# Agent Auth SDK

一个最小可发布的 Python SDK，用于完成三件事：

- 创建 Agent 身份、公私钥与 metadata
- 发送带签名的 Agent 消息或 HTTP 请求
- 从中心注册表 `/.well-known/agent.json` 解析并验证 Agent 身份

仓库当前只保留四类内容：

- SDK 主包：`agent_auth_sdk/`
- 中心 registry 服务：`agent_auth_registry/`
- 测试套件：`pytests/`
- 部署资产：`deploy/`

## 能力

- `agent://host/name` 格式的 `agent_id`
- Ed25519 密钥生成、签名、验签
- `SignedAgentMessage` 规范消息
- `/.well-known/agent.json` metadata 发布
- 中心注册表发布：`POST /registry/agents`
- 中心注册表发现：`GET /.well-known/agent.json`
- nonce 防重放
- metadata 缓存

## SDK 对外暴露接口

### 1. AgentInstance — 核心入口

一站式 Agent 实例封装，是开发者最常用的入口。聚合了身份创建、密钥管理、metadata 导出、发布和签名能力。

#### `AgentInstance.create()` — 创建 Agent 实例

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `domain` | `str` | ✅ | — | Agent 对外域名或 IP:Port，例如 `agent-a.example.com` |
| `name` | `str` | ✅ | — | Agent 名称，例如 `weather` |
| `organization` | `str` | ✅ | — | 所属组织名称 |
| `endpoint` | `str` | ✅ | — | Agent 业务 endpoint 完整 URL |
| `capabilities` | `list[str] \| None` | ❌ | `None` | 能力声明列表，例如 `["publish", "sign", "verify"]` |
| `kid` | `str` | ❌ | `"main"` | 密钥标识符 |
| `environment` | `str \| None` | ❌ | `None` | 部署环境标识 |
| `private_key_pem` | `str \| None` | ❌ | `None` | 已有私钥 PEM，不传则自动生成 Ed25519 密钥对 |
| `public_key_pem` | `str \| None` | ❌ | `None` | 已有公钥 PEM（传入时必须同时传 private_key_pem） |

**返回** `AgentInstance`，包含以下属性：`agent_id`、`domain`、`name`、`organization`、`endpoint`、`kid`、`private_key_pem`、`public_key_pem`、`public_key_base64url`、`capabilities`、`metadata`。

---

#### `agent.save_keys(output_dir)` — 保存密钥到文件

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `output_dir` | `str \| Path` | ✅ | 密钥输出目录 |

**返回** `dict[str, Path]` — `{"private_key.pem": Path, "public_key.pem": Path, "public_key.base64url": Path}`。

---

#### `agent.export_metadata(output_dir)` — 导出 well-known metadata 文件

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `output_dir` | `str \| Path` | ✅ | 输出目录，在其下创建 `.well-known/agent.json` |

**返回** `Path` — 生成的文件路径。

---

#### `await agent.publish()` — 发布 metadata 到中心注册服务器 (async)

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `registry_url` | `str` | ✅ | — | 注册中心接口地址 |
| `publisher` | `str \| None` | ❌ | `None` | 发布方标识 |
| `token` | `str \| None` | ❌ | `None` | 注册中心 Bearer Token |
| `http_client` | `httpx.AsyncClient \| None` | ❌ | `None` | 可复用 HTTP 客户端 |
| `timeout_seconds` | `float` | ❌ | `10.0` | 请求超时秒数 |

**返回** `dict` — 注册中心的响应 JSON。

---

#### `await agent.sign_message()` — 对 Agent 间消息签名 (async)

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `payload` | `bytes \| str \| dict \| list \| None` | ✅ | — | 消息体 |
| `payload_type` | `str` | ❌ | `"application/json"` | 消息体类型 |
| `recipient` | `str \| None` | ❌ | `None` | 接收方 agent_id |
| `message_type` | `str \| None` | ❌ | `None` | 消息类型标签 |

**返回** `SignedAgentMessage`

---

#### `await agent.sign_http()` — 对 HTTP 请求签名 (async)

便捷方法，内部委托给 `sign_http_request()`，自动使用实例的 `agent_id` 和 `signer`。其他参数透传。

---

### 2. 密钥与身份

#### `generate_ed25519_keypair(*, kid="main")` — 生成 Ed25519 密钥对

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `kid` | `str` | ❌ | `"main"` | 密钥标识符 |

**返回** `GeneratedKeyPair` — `private_key_pem`, `public_key_pem`, `public_key_base64url`, `kid`。

---

#### `build_agent_id(host, agent_name)` — 构造 agent_id

**返回** `str`，格式 `agent://host/name`。

---

#### `parse_agent_id(agent_id)` — 解析 agent_id

**返回** `ParsedAgentId` — `raw`, `host`, `agent_name`, `path_segments`。

---

### 3. 消息签名与验签

当不使用 `AgentInstance` 封装、需要独立调用签名/验签逻辑时使用。

#### `await sign_agent_message()` / `sign_agent_message_sync()`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `agent_id` | `str` | ✅ | — | 发送方 agent_id |
| `signer` | `Signer` | ✅ | — | 签名器实例（`LocalPemSigner` 或 `CallableSigner`） |
| `payload` | `bytes \| str \| dict \| list \| None` | ✅ | — | 消息体 |
| `payload_type` | `str` | ❌ | `"application/json"` | 消息体 MIME 类型 |
| `recipient` | `str \| None` | ❌ | `None` | 接收方 agent_id |
| `message_type` | `str \| None` | ❌ | `None` | 消息类型标签 |
| `timestamp` | `datetime \| str \| None` | ❌ | `None` | 自定义时间戳（默认当前 UTC） |
| `nonce` | `str \| None` | ❌ | `None` | 自定义 nonce（默认 UUID4） |

**返回** `SignedAgentMessage`

---

#### `await verify_agent_message()` / `verify_agent_message_sync()`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `message` | `SignedAgentMessage \| dict` | ✅ | — | 待验证的签名消息 |
| `nonce_store` | `NonceStore` | ✅ | — | 防重放存储（如 `InMemoryNonceStore`） |
| `http_client` | `httpx.AsyncClient` | ✅ | — | 用于获取对方 metadata 的 HTTP 客户端 |
| `cache` | `MetadataCache \| None` | ❌ | `None` | metadata 缓存 |
| `config` | `VerificationConfig \| None` | ❌ | `None` | 验签配置（控制 profile 等） |
| `resolver_config` | `MetadataResolverConfig \| None` | ❌ | `None` | metadata 解析配置（可指定 registry_url） |
| `now` | `datetime \| None` | ❌ | `None` | 当前时间（用于时间戳校验） |

**返回** `VerificationSuccess`（`ok=True`）或 `VerificationFailure`（`ok=False`）。

---

### 4. HTTP 请求签名与验签

#### `await sign_http_request()` / `sign_http_request_sync()`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `method` | `str` | ✅ | — | HTTP 方法 |
| `url` | `str` | ✅ | — | 请求 URL |
| `body` | `bytes \| str \| dict \| list \| None` | ✅ | — | 请求体 |
| `agent_id` | `str` | ✅ | — | 发送方 agent_id |
| `signer` | `Signer` | ✅ | — | 签名器实例 |
| `headers` | `dict[str, str] \| None` | ❌ | `None` | 已有请求头（签名头会合并进去） |
| `config` | `SigningConfig \| None` | ❌ | `None` | 签名配置 |
| `timestamp` | `str \| None` | ❌ | `None` | 自定义时间戳 |
| `nonce` | `str \| None` | ❌ | `None` | 自定义 nonce |

**返回** `SignatureHeaders` — `headers`（合并签名头后的完整请求头）、`canonical`、`body_digest`。

签名头包含：`x-agent-id`、`x-agent-kid`、`x-agent-timestamp`、`x-agent-nonce`、`x-agent-signature`、`x-agent-signature-input`。

---

#### `await verify_http_request()` / `verify_http_request_sync()`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `method` | `str` | ✅ | — | HTTP 方法 |
| `url` | `str` | ✅ | — | 请求 URL |
| `headers` | `dict[str, str]` | ✅ | — | 请求头（含签名头） |
| `body` | `bytes \| str \| dict \| list \| None` | ✅ | — | 请求体 |
| `nonce_store` | `NonceStore` | ✅ | — | 防重放存储 |
| `http_client` | `httpx.AsyncClient` | ✅ | — | 用于获取 metadata 的 HTTP 客户端 |
| `cache` | `MetadataCache \| None` | ❌ | `None` | metadata 缓存 |
| `config` | `VerificationConfig \| None` | ❌ | `None` | 验签配置 |
| `resolver_config` | `MetadataResolverConfig \| None` | ❌ | `None` | metadata 解析配置 |
| `now` | `datetime \| None` | ❌ | `None` | 当前时间 |
| `request_id` | `str \| None` | ❌ | `None` | 请求追踪 ID |

**返回** `VerificationSuccess` 或 `VerificationFailure`。

---

### 5. Metadata 解析

#### `await resolve_agent()` — 从 well-known 或注册表获取 Agent metadata (async)

验签流程中会自动调用，也可以独立使用。

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `agent_id` | `str` | ✅ | — | 目标 agent_id |
| `http_client` | `httpx.AsyncClient` | ✅ | — | HTTP 客户端 |
| `profile` | `RuntimeProfile` | ❌ | `TEST_PROFILE` | 安全策略 profile |
| `cache` | `MetadataCache \| None` | ❌ | `None` | 缓存实例 |
| `config` | `MetadataResolverConfig \| None` | ❌ | `None` | 解析配置（设置 `registry_url` 后优先走注册表） |

**返回** `ResolveResult` — `metadata`, `resolved_at`, `etag`, `source_url`。

---

### 6. 签名器

#### `LocalPemSigner` — 本地 PEM 签名器

| 构造参数 | 类型 | 必填 | 说明 |
|----------|------|------|------|
| `private_key_pem` | `str` | ✅ | PEM 格式 Ed25519 私钥 |
| `kid_value` | `str` | ✅ | 密钥标识符 |

---

#### `CallableSigner` — 外部签名器（KMS / HSM）

| 构造参数 | 类型 | 必填 | 默认值 | 说明 |
|----------|------|------|--------|------|
| `kid_value` | `str` | ✅ | — | 密钥标识符 |
| `sign_callable` | `Callable[[bytes], Awaitable[bytes]]` | ✅ | — | 异步签名函数 |
| `algorithm_name` | `str` | ❌ | `"Ed25519"` | 签名算法 |

---

### 7. 存储

验签时必须提供 nonce 存储（防重放），建议提供 metadata 缓存（减少网络请求）。

#### Nonce 防重放

| 类 | 适用场景 |
|----|----------|
| `InMemoryNonceStore` | 单进程服务，进程重启后清空 |
| `RedisNonceStore` | 多实例部署，构造参数：`redis_client`、`prefix`（默认 `"agent_identity:nonce:"`） |

#### Metadata 缓存

| 类 | 适用场景 |
|----|----------|
| `InMemoryMetadataCache` | 单进程服务，进程重启后丢失 |
| `FileMetadataCache` | 需要重启后保留缓存，构造参数：`db_path`（SQLite 文件路径） |

---

### 8. 配置

#### `SigningConfig` — 签名配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `profile` | `RuntimeProfile` | `TEST_PROFILE` | 运行时安全策略 |
| `include_signature_input_header` | `bool` | `True` | 是否输出 `x-agent-signature-input` 头 |

#### `VerificationConfig` — 验签配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `profile` | `RuntimeProfile` | `TEST_PROFILE` | 运行时安全策略 |
| `require_signature_input_header` | `bool` | `True` | 是否要求 `x-agent-signature-input` 头必须存在 |

#### `MetadataResolverConfig` — Metadata 解析配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `profile` | `RuntimeProfile` | `TEST_PROFILE` | 运行时安全策略 |
| `cache_ttl_seconds` | `int \| None` | `None` | 缓存 TTL（None 则用 profile 默认值） |
| `request_timeout_seconds` | `float` | `10.0` | 请求超时秒数 |
| `registry_url` | `str \| None` | `None` | 中心注册表地址，设置后优先从注册表解析 |

#### `RuntimeProfile` — 运行时安全策略

| Profile | `allow_http` | `allow_ip_host` | `clock_skew_seconds` | `cache_ttl_seconds` | `nonce_ttl_seconds` |
|---------|-------------|----------------|---------------------|--------------------|-------------------|
| `TEST_PROFILE` | ✅ | ✅ | 300 | 300 | 600 |
| `STRICT_PROFILE` | ❌ | ❌ | 120 | 300 | 600 |

---

### 9. 主要数据模型

开发者会作为参数传入或作为返回值收到的数据结构：

| 模型 | 角色 | 关键字段 |
|------|------|----------|
| `AgentMetadata` | Agent 身份文档 | `agent_id`, `domain`, `name`, `organization`, `endpoint`, `capabilities`, `keys` |
| `AgentKey` | 公钥条目 | `kid`, `alg`, `status`, `public_key_pem`, `public_key_base64url` |
| `SignedAgentMessage` | 签名消息 | `agent_id`, `kid`, `timestamp`, `nonce`, `payload`, `signature` |
| `VerificationSuccess` | 验签成功 | `ok=True`, `agent_id`, `kid`, `metadata` |
| `VerificationFailure` | 验签失败 | `ok=False`, `code`（错误码）, `reason`（错误原因） |
| `GeneratedKeyPair` | 生成密钥对 | `private_key_pem`, `public_key_pem`, `public_key_base64url`, `kid` |

---

### 10. 错误码

验签失败时 `VerificationFailure.code` 返回以下错误码：

| 错误码 | 含义 |
|--------|------|
| `INVALID_AGENT_ID` | agent_id 格式不合法 |
| `INVALID_METADATA` | metadata 内容不合法 |
| `METADATA_FETCH_FAILED` | 无法获取 Agent metadata |
| `METADATA_HOST_MISMATCH` | metadata 中的 host 与 agent_id 声明的 host 不一致 |
| `KEY_NOT_FOUND` | 未找到对应 kid 的公钥 |
| `KEY_REVOKED` | 对应密钥已被吊销 |
| `KEY_EXPIRED` | 对应密钥已过期 |
| `SIGNATURE_INVALID` | 签名验证不通过 |
| `TIMESTAMP_EXPIRED` | 时间戳超出允许偏差 |
| `NONCE_REPLAYED` | nonce 已被使用（重放攻击） |
| `POLICY_REJECTED` | 安全策略拒绝 |

## 安装

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
```

## 最小使用方式

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.create(
    domain="agent-a.example.com",
    name="weather",
    organization="A",
    endpoint="https://agent-a.example.com/invoke",
    capabilities=["publish", "sign", "verify"],
)

agent.save_keys("runtime/keys")
agent.export_metadata("runtime")
```

发布到中心 registry：

```python
await agent.publish(
    registry_url="http://192.144.228.237/registry/agents",
    publisher="developer-a",
    token="your-registry-token",
)
```

## CLI

生成密钥：

```bash
agent-auth-sdk keygen
```

渲染 metadata：

```bash
agent-auth-sdk render-metadata --host demo.example.com --agent-name weather --endpoint https://demo.example.com/invoke --public-key-pem-path runtime/keys/public_key.pem
```

发布到中心 registry：

```bash
agent-auth-sdk publish-to-registry --metadata-path runtime/.well-known/agent.json --registry-url http://192.144.228.237/registry/agents --token your-registry-token
```

从中心仓库解析：

```bash
agent-auth-sdk inspect-metadata agent://demo.example.com/weather --registry-url http://192.144.228.237/.well-known/agent.json
```

## 启动 registry 服务

```bash
set AGENT_REGISTRY_PATH=runtime/registry/.well-known/agent.json
set AGENT_REGISTRY_PORT=8008
python -m agent_auth_registry.run
```

## 测试

```bash
pytest
```

## 部署

CentOS 部署方案见 [deploy/DEPLOY_BETA_V1.md]。
