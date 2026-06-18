# Agent Auth SDK — 核心接口文档

本文档描述 Agent Auth SDK 对开发者暴露的 9 个核心接口，包括每个接口的用途、输入参数、返回值结构和内部处理逻辑。

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
- `source_url: str | None` — metadata 来源 URL

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

**用途**：安全轮换 Registry 中的 active signing key。将当前所有 active key 标记为 inactive，并新增一个 active key。需要同时证明旧 key 可控（签名完整请求）和新 key 可控（签名 proof）。

> **提示**：若需要保留已有 active key 的同时添加新 key，请使用 [`add_key()`](#7-添加额外活跃密钥)；若需要显式撤销某个泄露的 key，请使用 [`revoke_key()`](#8-撤销密钥)。

提供两种使用方式：

**方式 A — 外部 signer（兼容模式）：**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `new_signer` | `Signer` | 是 | 新 key 的签名器实例 |
| `new_public_key_pem` | `str` | 是 | 新 key 的 PEM 格式公钥 |
| `new_kid` | `str` | 是 | 新 key 的标识符 |

**方式 B — Vault 托管（推荐）：**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `new_key_name` | `str` | 是 | 新 key 在 Vault Transit 中的名称，SDK 自动创建 ecdsa-p256 key、读取公钥、构造 signer |

**公共参数：**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `registry_url` | `str` | 是 | Registry 轮换端点 URL |
| `client_id` | `str` | 是 | Developer client ID |
| `api_key` | `str` | 是 | Developer API key |
| `http_client` | `httpx.AsyncClient` | 否 | 复用的 HTTP 客户端 |
| `timeout_seconds` | `float` | 否 | 请求超时，默认 10.0 |

**返回值**：`dict` — Registry 返回的 JSON 响应体，含 `ok`、`agent_id`、`current_kid`。

**内部逻辑**：
1. 调用 `_resolve_new_key_signer(...)` 解析新 key 的 signer、公钥和 kid
2. 构造新的 `AgentKey(kid, "ES256", public_key_pem, status="active")`
3. 调用 `rotate_key_in_registry(...)` 执行双重签名 + Registry 通信
4. 成功后更新本地 `AgentInstance` 状态：所有旧 active key → `inactive`，追加新 key 为 `active`

**安全条件**（由 Registry 端强制）：
- Developer API key 必须有效
- 旧 active key 签名必须通过
- 新 key proof 签名必须通过
- Proof timestamp 必须在允许时间窗内
- Proof nonce 不能重放
- Owner 必须匹配（`agent_id → developer_id` 绑定）

---

## 7. 添加额外活跃密钥

### `AgentInstance.add_key()`

**用途**：为 Agent 添加额外活跃密钥，保留已有 active key 不变。适用于多地域部署、平滑算法迁移等场景。

> **与 `rotate_key()` 的区别**：`add_key()` 不会将已有 active key 标记为 inactive，允许多个活跃 key 并存；`rotate_key()` 会将所有旧 active key 标记为 inactive 并仅保留一个 active key。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `registry_url` | `str` | 是 | Registry add-key 端点 URL |
| `client_id` | `str` | 是 | Developer client ID |
| `api_key` | `str` | 是 | Developer API key |
| `new_signer` | `Signer` | 否 | 新 key 的签名器实例（方式 A） |
| `new_public_key_pem` | `str` | 否 | 新 key 的 PEM 格式公钥（方式 A） |
| `new_kid` | `str` | 否 | 新 key 的标识符（方式 A） |
| `new_key_name` | `str` | 否 | Vault Transit key 名称（方式 B，SDK 自动创建） |
| `http_client` | `httpx.AsyncClient` | 否 | 复用的 HTTP 客户端 |
| `timeout_seconds` | `float` | 否 | 请求超时，默认 10.0 |

**返回值**：`dict` — Registry 返回的 JSON 响应体，含 `ok`、`agent_id`、`added_kid`。

**内部逻辑**：
1. 调用 `_resolve_new_key_signer(...)` 解析新 key（Vault 或外部 signer）
2. 构造新的 `AgentKey(kid, "ES256", public_key_pem, status="active")`
3. 调用 `add_key_in_registry(...)` 执行双重签名（旧 key 签名请求 + 新 key 签名 add-key proof）并提交
4. 成功后追加新 key 到本地 `metadata.keys`，**不修改已有 key 状态**

**安全条件**：与 `rotate_key()` 相同，使用独立域名分离的 canonical string（`add-key-new-key-proof-v1`）防止跨操作重放。

---

## 8. 撤销密钥

### `AgentInstance.revoke_key()`

**用途**：显式撤销一个密钥，将其加入 `revoked_kids` 黑名单。被撤销的 key 将在后续所有验签操作中被立即拒绝。适用于密钥泄露等安全应急场景。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `registry_url` | `str` | 是 | Registry revoke-key 端点 URL |
| `client_id` | `str` | 是 | Developer client ID |
| `api_key` | `str` | 是 | Developer API key |
| `kid_to_revoke` | `str` | 是 | 需要撤销的 key ID |
| `http_client` | `httpx.AsyncClient` | 否 | 复用的 HTTP 客户端 |
| `timeout_seconds` | `float` | 否 | 请求超时，默认 10.0 |

**返回值**：`dict` — Registry 返回的 JSON 响应体，含 `ok`、`agent_id`、`revoked_kid`。

**Raises**：
- `ValueError`：若 `kid_to_revoke` 不存在于 metadata 中，或是唯一的 active key（防锁死保护）

**内部逻辑**：
1. 校验 `kid_to_revoke` 存在于 `self.metadata.keys` 中
2. 校验不是唯一的 active key（防止锁死自己——必须先通过 `add_key()` 或 `rotate_key()` 建立新 active key）
3. 调用 `revoke_key_in_registry(...)` 用当前 active key 签名并提交
4. 成功后本地更新：kid 加入 `metadata.revoked_kids`，对应 key 的 `status` 改为 `"revoked"`

**防锁死规则**：不能撤销最后一个 active key。如果 `kid_to_revoke` 的 `status == "active"` 且 metadata 中只有一个 active key，SDK 会在本地抛出 `ValueError`，不会发出网络请求。

**安全条件**（由 Registry 端强制）：
- Developer API key 必须有效
- 当前 active key 签名必须通过
- Owner 必须匹配
- 不可撤销最后一个 active key（Registry 端同样强制检查）

---

## 9. 撤销 Agent

### `AgentInstance.revoke_agent()`

**用途**：撤销整个 Agent。撤销后 agent 从 Registry 公开文档中移除，所有后续操作（publish、rotate_key、add_key、revoke_key）均返回 410 `AGENT_REVOKED`。

> **注意**：此操作不可逆。如需恢复，必须用全新的 key 重新 publish。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `registry_url` | `str` | 是 | Registry revoke 端点 URL |
| `client_id` | `str` | 是 | Developer client ID |
| `api_key` | `str` | 是 | Developer API key |
| `http_client` | `httpx.AsyncClient` | 否 | 复用的 HTTP 客户端 |
| `timeout_seconds` | `float` | 否 | 请求超时，默认 10.0 |

**返回值**：`dict` — Registry 返回的 JSON 响应体，含 `ok`、`agent_id`。

**内部逻辑**：
1. 调用 `revoke_agent_in_registry(...)` 用当前 active key 签名并提交
2. Registry 端将 ownership 状态改为 `"revoked"`，agent 从公开文档中排除
3. 后续任何对该 agent 的操作均被 `_assert_agent_active()` 拦截

**安全条件**（由 Registry 端强制）：
- Developer API key 必须有效
- 当前 active key 签名必须通过
- Owner 必须匹配

**Admin CLI 等效操作**：
```bash
source /etc/agent-auth/env.sh
source /opt/agent_auth_sdk/.venv/bin/activate
agent-auth-registry-admin revoke-agent --agent-id agent://<host>/<name>
```

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
