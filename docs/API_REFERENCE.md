# Agent Auth SDK — 核心接口文档

本文档描述 Agent Auth SDK 对开发者暴露的 6 个核心接口，包括每个接口的用途、输入参数、返回值结构和内部处理逻辑。

---

## 1. 创建 Agent Metadata

### `AgentInstance.from_vault()`

**用途**：从 HashiCorp Vault Transit 创建 Agent 实例，适用于生产环境。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `domain` | `str` | 是 | Agent 所属域名，也是 `agent_id` 的 host 部分 |
| `name` | `str` | 是 | Agent 名称，也是 `agent_id` 的 path 部分 |
| `organization` | `str` | 是 | 组织名，写入 metadata |
| `endpoint` | `str` | 是 | Agent 服务入口 URL |
| `vault_addr` | `str` | 是 | Vault 服务地址 |
| `transit_mount` | `str` | 是 | Vault Transit mount path |
| `key_name` | `str` | 是 | Vault Transit key name |
| `vault_token_file` | `str \| Path` | 推荐 | Vault token 文件路径，生产推荐 |
| `vault_token` | `str` | 否 | dev/test-only raw token |
| `allow_insecure_raw_token` | `bool` | 否 | 显式开启 raw token 模式（仅限 dev/test） |
| `namespace` | `str` | 否 | Vault Enterprise namespace |
| `verify` | `bool \| str` | 否 | TLS 校验，默认 `True` |
| `capabilities` | `list[str]` | 否 | Agent 能力声明 |
| `environment` | `str` | 否 | 运行环境标识（如 `"prod"`） |
| `kid` | `str` | 否 | 自定义 key id，默认 `"vault:{transit_mount}/{key_name}"` |
| `auto_create_key` | `bool` | 否 | 若为 `True`，key 不存在时自动在 Vault Transit 中创建 `ecdsa-p256` key，默认 `False` |

**返回值**：`AgentInstance` 对象，包含完整的 agent 身份信息和 metadata。

**内部逻辑**：
1. 使用传入参数构造 `VaultKmsConfig`
2. _若 `auto_create_key=True`_：检查 Transit key 是否存在，若不存在则调用 `create_key(name, key_type="ecdsa-p256")` 自动创建
3. 创建 `VaultTransitSigner`，连接 Vault 服务
4. 调用 `signer.validate_access()` 校验签名权限
5. 调用 `resolve_vault_public_key()` 从 Transit 获取 ECDSA-P256 公钥
6. 完成 AgentInstance 构造并返回

> **Vault 权限要求**：`auto_create_key=True` 时，Vault token 需要对 `transit/keys/*` 有 `create` 或 `update` 权限。详见 [VAULT_SETUP.md](VAULT_SETUP.md)。

---

### `AgentInstance.export_metadata(output_dir)`

**用途**：将 Agent metadata 导出为 `/.well-known/agent.json` 文件，供其他 Agent 发现。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `output_dir` | `str \| Path` | 是 | 输出目录，文件写入 `{output_dir}/.well-known/agent.json` |

**返回值**：`Path` — 写入的文件路径。

**内部逻辑**：创建 `{output_dir}/.well-known/` 目录，将 `self.metadata` 以 JSON 格式写入 `agent.json`。

---

## 2. 发布 Agent 到 Registry

### `AgentInstance.publish()`

**用途**：将 Agent metadata 发布到中心 Registry 服务器，使其他 Agent 可以通过 Registry 发现本 Agent。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `registry_url` | `str` | 是 | Registry 发布端点 URL |
| `client_id` | `str` | 是 | Developer client ID |
| `api_key` | `str` | 是 | Developer API key |
| `http_client` | `httpx.AsyncClient` | 否 | 复用的 HTTP 客户端 |
| `timeout_seconds` | `float` | 否 | 请求超时，默认 10.0 |

**返回值**：`dict` — Registry 返回的 JSON 响应体。

**内部逻辑**：
1. 构造 publish payload：`{"agent_id", "metadata", "publish_intent": "upsert_metadata"}`
2. 调用 `sign_registry_publish_request(...)` 对 publish 请求签名——使用 Agent 的 active key 对 canonical string 签名，生成 `x-agent-*` 签名 headers
3. 附加 `Authorization: Bearer {api_key}` header
4. POST 到 `registry_url`，携带签名 headers 和 JSON body
5. 校验 HTTP 响应状态（非 2xx 抛出 `httpx.HTTPStatusError`）
6. 返回响应 JSON

**安全保证**：Registry 会校验 developer API key 和 Agent key 签名双重认证；首次发布建立 `agent_id → developer_id` owner 绑定。

---

## 3. 签名消息

### `AgentInstance.sign_http()`

**用途**：为 HTTP 请求（如跨 Agent 调用）生成签名 headers，接收方可据此验证请求来源。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | `str` | 是 | HTTP 方法（如 `"POST"`） |
| `url` | `str` | 是 | 请求 URL |
| `body` | `bytes \| str \| dict \| list` | 否 | 请求体 |
| `*` | `**kwargs` | 否 | 透传至内部 `sign_http_request()` |

**返回值**：`SignatureHeaders` 对象，包含：
- `headers: dict[str, str]` — 签名相关 headers（`x-agent-id`、`x-agent-kid`、`x-agent-timestamp`、`x-agent-nonce`、`x-agent-signature`、`x-agent-signature-input`、`host`）
- `canonical: str` — 签名用的 canonical string（调试用）
- `body_digest: str` — 请求体的 SHA-256 base64url 摘要

**内部逻辑**：
1. 自动填充 `agent_id` 和 `signer`（从 `self` 获取）
2. 调用 `sign_http_request(...)` 构造 canonical request string 并签名
3. 返回 `SignatureHeaders`

---

### `AgentInstance.sign_message()`

**用途**：生成规范签名消息，用于 Agent 间异步消息传递（非 HTTP 场景）。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `payload` | `bytes \| str \| dict \| list \| None` | 是 | 消息载荷 |
| `payload_type` | `str` | 否 | 载荷类型，默认 `"application/json"` |
| `recipient` | `str` | 否 | 目标 Agent 的 agent_id（如 `"agent://example.com/resolver"`） |
| `message_type` | `str` | 否 | 消息类型标识（如 `"ticket.update"`） |

**返回值**：`SignedAgentMessage` 对象，包含 `agent_id`、`kid`、`alg`、`timestamp`、`nonce`、`payload_type`、`payload`、`signature`、`recipient`、`message_type` 等字段。

**内部逻辑**：
1. 调用 `parse_agent_id(self.agent_id)` 校验格式
2. 生成 `kid`（从 signer）和 `timestamp`（UTC）、`nonce`（UUID4）
3. 调用 `build_canonical_message(...)` 构造稳定的签名原文——按固定顺序拼接 `agent-message-v1`、`agent_id`、`kid`、`timestamp`、`nonce`、`payload_type`、`payload_digest`（SHA-256 base64url）、`recipient`、`message_type`
4. 调用 `signer.sign(canonical.encode("utf-8"))` 对原文签名
5. 返回 `SignedAgentMessage`（签名以 base64url 编码存储在 `signature` 字段）

---

## 4. 验签

### `verify_http_request()`

**用途**：验证 HTTP 请求的签名，确认请求来源 Agent 的身份和完整性。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | `str` | 是 | HTTP 方法 |
| `url` | `str` | 是 | 请求 URL |
| `headers` | `dict[str, str]` | 是 | 请求 headers（含签名 headers） |
| `body` | `bytes \| str \| dict \| list \| None` | 是 | 请求体 |
| `nonce_store` | `NonceStore` | 是 | Nonce 存储，用于防重放 |
| `http_client` | `httpx.AsyncClient` | 是 | HTTP 客户端（用于获取 metadata） |
| `cache` | `MetadataCache` | 否 | Metadata 缓存 |
| `config` | `VerificationConfig` | 否 | 验签配置，默认使用 `STRICT_PROFILE` |
| `resolver_config` | `MetadataResolverConfig` | 否 | Metadata 解析配置 |
| `now` | `datetime` | 否 | 参考时间（默认当前 UTC） |
| `request_id` | `str` | 否 | 请求追踪 ID |

**返回值**：
- `VerificationSuccess`（`ok=True`）：包含 `agent_id`、`kid`、`metadata`（`AgentMetadata`）、`canonical`（签名原文）、`request_id`
- `VerificationFailure`（`ok=False`）：包含 `code`（错误码）、`reason`（失败原因）

**内部逻辑**（按序号执行，任一步失败返回 `VerificationFailure`）：
1. 规范化请求 headers（lowercase key）
2. 提取 `x-agent-id`、`x-agent-kid`、`x-agent-timestamp`、`x-agent-nonce`、`x-agent-signature` 必要 header
3. 校验 `x-agent-signature-input` header 的存在性（根据 `config.require_signature_input_header`）
4. 调用 `parse_agent_id(agent_id)` 校验 agent_id 格式
5. 解析并校验 `timestamp` 是否在允许的时间偏移内（由 `profile.clock_skew_seconds` 控制）
6. 以 `nonce_key = "{agent_id}:{nonce}"` 检查 nonce 是否已被使用（防重放）
7. 调用 `resolve_agent(agent_id, ...)` 获取发送方 Agent 的 metadata（优先 registry，后备 well-known URL）
8. 调用 `select_verification_key(metadata, kid, now)` 从 metadata 中选择匹配 kid 的 active key，校验其未过期、未撤销
9. 调用 `build_canonical_request(...)` 重建签名原文
10. 调用 `verify_signature(public_key_pem, data, signature_base64url, alg)` 使用公钥验签
11. 记录 nonce 到 `nonce_store`
12. 返回 `VerificationSuccess`

---

### `verify_agent_message()`

**用途**：验证 Agent 间规范消息的签名。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `message` | `SignedAgentMessage \| dict` | 是 | 待验证的消息 |
| `nonce_store` | `NonceStore` | 是 | Nonce 存储 |
| `http_client` | `httpx.AsyncClient` | 是 | HTTP 客户端 |
| `cache` | `MetadataCache` | 否 | Metadata 缓存 |
| `config` | `VerificationConfig` | 否 | 验签配置 |
| `resolver_config` | `MetadataResolverConfig` | 否 | Metadata 解析配置 |
| `now` | `datetime` | 否 | 参考时间 |

**返回值**：同 `verify_http_request()`，成功返回 `VerificationSuccess`（含 `message` 字段），失败返回 `VerificationFailure`。

**内部逻辑**：
1. 若 message 是 `dict`，则用 `SignedAgentMessage.model_validate(message)` 反序列化
2. 校验 `agent_id` 格式
3. 校验 `timestamp` 是否在允许的时间偏移内
4. 检查 nonce 是否重放
5. 通过 `resolve_agent(...)` 获取发送方 metadata
6. 通过 `select_verification_key(...)` 选择匹配的 active key
7. 调用 `build_canonical_message(...)` 重建签名原文
8. 调用 `verify_signature(...)` 验签
9. 记录 nonce，返回结果

---

## 5. 查询 Metadata 表

### `resolve_agent()`

**用途**：解析指定 Agent 的 metadata，优先从中心 Registry 查询，后备从 `/.well-known/agent.json` 获取。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `agent_id` | `str` | 是 | 待查询的 agent_id（如 `"agent://example.com/weather"`） |
| `profile` | `RuntimeProfile` | 否 | 安全策略，默认 `STRICT_PROFILE` |
| `http_client` | `httpx.AsyncClient` | 是 | HTTP 客户端 |
| `cache` | `MetadataCache` | 否 | Metadata 缓存实现 |
| `config` | `MetadataResolverConfig` | 否 | 解析配置 |

**返回值**：`ResolveResult`，包含：
- `metadata: AgentMetadata` — Agent 的完整身份 metadata
- `resolved_at: datetime` — 解析时间
- `etag: str | None` — HTTP ETag（用于条件请求）
- `source_url: str` — metadata 来源 URL

**内部逻辑**：
1. 若提供了 `cache`，检查缓存中是否有有效的 metadata，若有则携带 `If-None-Match` header
2. 若 `config.registry_url` 已配置：
   - a. 调用 `_resolve_from_registry(agent_id, registry_url, ...)` — GET `registry_url` 获取 `AgentRegistryDocument`，遍历 `document.agents` 找到匹配 `agent_id` 的条目
   - b. 调用 `validate_metadata(metadata, profile)` 校验 metadata（endpoint scheme、host 类型、duplicate kid）
   - c. 调用 `assert_subject_match(agent_id, domain)` 校验 agent_id 与 domain 一致性
   - d. 成功则更新缓存并返回 `ResolveResult`
   - e. 若 registry 查询失败（异常），fall through 到 well-known 路径
3. 若未配置 registry 或 registry 查询失败：
   - a. 根据 `agent_id` 的 host 部分和 `profile` 构造 well-known URL：`{scheme}://{host}/.well-known/agent.json`
   - b. GET 请求 metadata，支持 ETag 条件请求（304 响应时返回缓存）
   - c. 校验 metadata 内容
   - d. 更新缓存并返回 `ResolveResult`
4. 若所有路径均失败且无缓存可用，向上抛出异常

---

## 6. 轮换 Agent Key

### `AgentInstance.rotate_key()`

**用途**：安全轮换 Registry 中的 active signing key。需要同时证明旧 key 可控（签名完整请求）和新 key 可控（签名 proof）。

提供两种使用方式：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `registry_url` | `str` | 是 | Registry 轮换端点 URL |
| `client_id` | `str` | 是 | Developer client ID |
| `api_key` | `str` | 是 | Developer API key |
| `new_key_name` | `str` | 是 | 新 key 在 Vault Transit 中的名称，SDK 自动创建 ecdsa-p256 key、读取公钥、构造 signer |
| `http_client` | `httpx.AsyncClient` | 否 | 复用的 HTTP 客户端 |
| `timeout_seconds` | `float` | 否 | 请求超时，默认 10.0 |

**返回值**：`dict` — Registry 返回的 JSON 响应体。

**内部逻辑**：

_SDK 自动创建新 key_：
1. 从当前 signer 的 Vault 配置中复制连接参数
2. 调用 `_ensure_transit_key(new_config)` 自动创建 ecdsa-p256 key
3. 调用 `resolve_vault_public_key(new_config)` 读取公钥
4. 构造新 `VaultTransitSigner` 和 `new_kid`

_双签名 + 提交_：
1. 构造新的 `AgentKey(new_kid, "ES256", new_public_key_pem, status="active")`
2. 调用 `sign_registry_new_key_proof(agent_id, new_key, client_id, host, signer=new_signer)` 生成新 key 的 proof 签名——proof 的 canonical string 绑定 `agent_id`、`new_key.kid`、新公钥指纹、timestamp、nonce、`client_id` 和 `host`，由新 signer 签名证明私钥可控
3. 构造轮换 payload：`{"agent_id", "new_key", "new_key_proof_headers"}`
4. 调用 `sign_registry_publish_request(path, host, payload, agent_id, client_id, signer=current_signer)` 用 **旧** active key 签名完整轮换请求
5. 附加 `Authorization: Bearer {api_key}` header
6. POST 到 `registry_url`，携带双重签名
7. 校验 HTTP 响应状态
8. 成功后更新本地 `AgentInstance` 状态：更新 `kid`、`public_key_pem`、`public_key_base64url`、`signer_override`，并将 metadata 中旧 key 标记为 `inactive`

**安全条件**（由 Registry 端强制）：
- Developer API key 必须有效
- 旧 active key 签名必须通过
- 新 key proof 签名必须通过
- Proof timestamp 必须在允许时间窗内
- Proof nonce 不能重放
- Owner 必须匹配（`agent_id → developer_id` 绑定）

---

## 辅助配置类

上述核心接口依赖以下配置类和存储实现，它们也在 SDK 顶层导出：

### `VerificationConfig`

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `profile` | `RuntimeProfile` | `STRICT_PROFILE` | 验签安全策略 |
| `require_signature_input_header` | `bool` | `True` | 是否要求 `x-agent-signature-input` header |

### `MetadataResolverConfig`

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `profile` | `RuntimeProfile` | `STRICT_PROFILE` | Metadata 解析安全策略 |
| `cache_ttl_seconds` | `int` | `None` | 覆盖 profile 中的缓存 TTL |
| `request_timeout_seconds` | `float` | `10.0` | Metadata 请求超时 |
| `registry_url` | `str` | `None` | 中心 Registry 聚合文档地址 |

### `InMemoryNonceStore`

内存 nonce 存储，基于 Python `dict`，适用于单进程 demo 或测试场景。

### `FileMetadataCache`

基于 SQLite 文件的持久化 metadata 缓存，适用于生产单实例部署。

> **注意**：其他存储实现（`RedisNonceStore`、`InMemoryMetadataCache`）、协议类（`NonceStore`、`MetadataCache`、`Signer`）、数据模型等可通过子模块路径访问，详见 [README.md](../README.md) 和模块源码。
