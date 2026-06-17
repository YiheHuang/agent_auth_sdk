# 中心 Registry `agent.json` 结构文档

## 概述

Agent Auth 协议中有**两种** `/.well-known/agent.json`：

| 类型 | 位置 | 内容 |
|------|------|------|
| **单个 Agent 的 metadata** | `https://{agent_host}/.well-known/agent.json` | 一个 Agent 的身份、公钥、能力声明 |
| **中心 Registry 聚合文档** | `https://{registry_host}/.well-known/agent.json` | 所有已发布 Agent 的 metadata 聚合 |

本文档重点描述**中心 Registry 聚合文档**的结构。单个 Agent 的 metadata 结构与之共享 `AgentMetadata` 模型，只是不包含外层的 `AgentRegistryDocument` 和 `AgentRegistryEntry` 包装。

---

## JSON 层级总览

```
AgentRegistryDocument          ← 顶层，Registry 对外暴露
├── version: str               ← 文档版本
├── registry_type: str         ← 固定 "agent_registry"
├── updated_at: datetime       ← 文档生成时间
└── agents: [                  ← Agent 条目数组
    AgentRegistryEntry
    ├── agent_id: str          ← Agent 唯一标识
    ├── published_at: datetime ← 发布时间
    ├── publisher: str|null    ← 发布者标识
    └── metadata: AgentMetadata ← 核心 metadata
        ├── version: str
        ├── agent_id: str
        ├── domain: str
        ├── name: str
        ├── organization: str
        ├── endpoint: str
        ├── capabilities: [str]
        ├── keys: [AgentKey]
        │   ├── kid: str
        │   ├── alg: "ES256"
        │   ├── status: "active"|"inactive"
        │   ├── public_key_base64url: str|null
        │   ├── public_key_pem: str|null
        │   ├── not_before: datetime|null
        │   └── not_after: datetime|null
        ├── revoked_kids: [str]
        ├── updated_at: datetime
        ├── environment: str|null
        ├── signing_policy: dict|null
        ├── verification_policy: dict|null
        └── audit: AgentAuditConfig|null
            ├── mode: "jsonl"|"sqlite"|"custom"
            └── destination: str|null
```

---

## 一、顶层：`AgentRegistryDocument`

Registry 对外暴露的 `/.well-known/agent.json` 顶层结构。

```json
{
  "version": "1.0",
  "registry_type": "agent_registry",
  "updated_at": "2026-06-17T08:30:00.123456Z",
  "agents": [ ... ]
}
```

### 字段说明

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `version` | `string` | 是 | 文档格式版本，当前固定 `"1.0"` |
| `registry_type` | `string` | 是 | Registry 类型标识，固定 `"agent_registry"`，用于与其它 registry 类型区分 |
| `updated_at` | `string` (ISO 8601) | 是 | 文档生成时间戳（UTC）。每次 publish 或 rotate-key 成功后重新生成 |
| `agents` | `array` | 是 | 已注册 Agent 的条目列表，按 `agent_id` 字母序排列。空数组表示尚无 Agent 注册 |

> `updated_at` 由 `RegistryStore.render_public_document()` 调用 `datetime.now(timezone.utc)` 生成，反映的是文档渲染时间，而非最后一条 publish 时间。

---

## 二、`AgentRegistryEntry` — 单个 Agent 条目

`agents` 数组中每个元素的结构。

```json
{
  "agent_id": "agent://agent.example.com/weather",
  "metadata": { ... },
  "published_at": "2026-06-17T08:00:00.000000Z",
  "publisher": null
}
```

### 字段说明

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `agent_id` | `string` | 是 | Agent 唯一标识，格式 `agent://{host}/{name}`。在 Registry 中全局唯一 |
| `metadata` | `object` | 是 | Agent 的完整身份 metadata（详见第三节） |
| `published_at` | `string` (ISO 8601) | 是 | Agent 首次发布到 Registry 的时间。后续 publish（更新 metadata）不会改变此值 |
| `publisher` | `string` \| `null` | 否 | 发布者标识。当前实现中始终为 `null`（developer 身份由 Registry 内部 owner 绑定维护，不对外暴露） |

> `published_at` 在首次 `upsert_agent()` 时写入 `created_at` 字段，后续更新不会覆盖。这使得其他 Agent 可以知道某个 Agent ID 是何时首次注册的。

---

## 三、`AgentMetadata` — Agent 身份 Metadata（核心）

这是整个协议的核心数据结构，描述一个 Agent 的完整身份信息。

```json
{
  "version": "1.0",
  "agent_id": "agent://agent.example.com/weather",
  "domain": "agent.example.com",
  "name": "weather",
  "organization": "Example Lab",
  "endpoint": "https://agent.example.com/tasks/handle",
  "capabilities": ["weather.query", "sign", "verify"],
  "keys": [ ... ],
  "revoked_kids": [],
  "updated_at": "2026-06-17T08:00:00.000000Z",
  "environment": "prod",
  "signing_policy": {
    "canonical_request": "v1",
    "signed_message": "v1"
  },
  "verification_policy": {
    "resolve_via": "/.well-known/agent.json"
  },
  "audit": {
    "mode": "jsonl",
    "destination": null
  }
}
```

### 3.1 身份标识字段

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `version` | `string` | 是 | Metadata 格式版本，固定 `"1.0"` |
| `agent_id` | `string` | 是 | Agent 唯一标识，格式 `agent://{domain}/{name}`。**不可变**——publish 更新时若 agent_id 变化会被 Registry 拒绝（`IMMUTABLE_AGENT_ID`） |
| `domain` | `string` | 是 | Agent 所属域名。用于构造 well-known URL：`https://{domain}/.well-known/agent.json`。**不可变**（`IMMUTABLE_DOMAIN`） |
| `name` | `string` | 是 | Agent 名称，与 `domain` 共同组成 `agent_id`。**不可变**（`IMMUTABLE_NAME`） |
| `organization` | `string` | 是 | 所属组织名称，纯展示用途，无协议约束 |
| `endpoint` | `string` | 是 | Agent 的服务入口 URL（绝对 URL）。其他 Agent 向此地址发送任务请求。strict profile 下必须是 HTTPS URL |
| `environment` | `string` \| `null` | 否 | 运行环境标识，如 `"prod"`、`"staging"`、`"demo"` |

> **不可变字段**：`agent_id`、`domain`、`name` 在首次 publish 后不可修改。若需修改，必须创建新的 agent_id 并重新发布。

### 3.2 能力与权限字段

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `capabilities` | `array[string]` | 是 | Agent 的能力声明列表，如 `["weather.query", "sign", "verify", "publish"]`。目前为自由格式字符串数组，由业务层自行定义和校验 |

### 3.3 密钥字段

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `keys` | `array[AgentKey]` | 是 | 公钥列表，至少包含一把 `active` 状态的 key。详见第四节 |
| `revoked_kids` | `array[string]` | 是 | 已撤销的 key ID 列表。验签时若 `kid` 在此列表中直接拒绝（即使 key 列表中还有该 kid 的记录） |

> `keys` 可以包含多把 key（例如轮换后新旧 key 共存），但同一时刻只有一把 `status: "active"` 的 key 用于签名。其他 key 应为 `"inactive"`。

### 3.4 策略字段

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `signing_policy` | `object` \| `null` | 否 | 签名策略声明，当前固定 `{"canonical_request": "v1", "signed_message": "v1"}`。表明支持的签名规范版本 |
| `verification_policy` | `object` \| `null` | 否 | 验签策略声明，当前固定 `{"resolve_via": "/.well-known/agent.json"}`。表明 metadata 的解析方式 |

> 策略字段为扩展预留。未来可在此字段中声明支持的算法、nonce 有效期等。

### 3.5 审计与时间字段

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `updated_at` | `string` (ISO 8601) | 是 | Metadata 最后更新时间（UTC）。每次 publish 或 rotate-key 成功后会更新 |
| `audit` | `object` \| `null` | 否 | 审计配置，详见第五节 |

---

## 四、`AgentKey` — 公钥声明

`AgentMetadata.keys` 数组中每个元素的结构。

```json
{
  "kid": "vault:transit/weather-agent",
  "alg": "ES256",
  "status": "active",
  "public_key_base64url": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYH...\n-----END PUBLIC KEY-----",
  "not_before": null,
  "not_after": null
}
```

### 字段说明

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `kid` | `string` | 是 | Key ID，在 metadata 中唯一标识一把 key。Vault 托管时格式为 `"vault:{transit_mount}/{key_name}"`。验签时根据请求中的 `x-agent-kid` header 匹配 |
| `alg` | `string` | 是 | 签名算法。当前仅支持 `"ES256"`（ECDSA P-256 + SHA-256） |
| `status` | `string` | 是 | Key 状态。`"active"` — 当前用于签名和验签；`"inactive"` — 轮换后的旧 key，仅用于验签过渡期，不用于新签名 |
| `public_key_base64url` | `string` \| `null` | 条件必填 | 公钥的 DER 编码再 base64url 编码。与 `public_key_pem` 至少提供一个 |
| `public_key_pem` | `string` \| `null` | 条件必填 | 公钥的 PEM 格式。与 `public_key_base64url` 至少提供一个 |
| `not_before` | `string` \| `null` | 否 | 密钥生效时间（ISO 8601），在此时间之前 key 不可用于验签。`null` 表示立即生效 |
| `not_after` | `string` \| `null` | 否 | 密钥过期时间（ISO 8601），在此时间之后 key 不可用于验签。`null` 表示永不过期 |

> **密钥轮换后的状态**：轮换时 Registry 将旧 active key 的 `status` 改为 `"inactive"`，新增 `status: "active"` 的新 key。验签时 `select_verification_key()` 只匹配 `status == "active"` 的 key。

---

## 五、`AgentAuditConfig` — 审计配置

`AgentMetadata.audit` 的结构，可选扩展字段。

```json
{
  "mode": "jsonl",
  "destination": null
}
```

### 字段说明

| 字段 | JSON 类型 | 必填 | 说明 |
|------|----------|------|------|
| `mode` | `string` | 否 | 审计日志输出模式。`"jsonl"` — JSON Lines 文件；`"sqlite"` — SQLite 数据库；`"custom"` — 自定义。默认 `"jsonl"` |
| `destination` | `string` \| `null` | 否 | 审计输出路径。`null` 表示使用默认路径 |

> `audit` 字段允许额外属性（`extra="allow"`），供网关或厂商自定义扩展。

---

## 六、完整 JSON 示例

以下是一个包含两个 Agent 的 Registry 聚合文档示例：

```json
{
  "version": "1.0",
  "registry_type": "agent_registry",
  "updated_at": "2026-06-17T08:30:00.123456Z",
  "agents": [
    {
      "agent_id": "agent://127.0.0.1:8101/intake-agent",
      "metadata": {
        "version": "1.0",
        "agent_id": "agent://127.0.0.1:8101/intake-agent",
        "domain": "127.0.0.1:8101",
        "name": "intake-agent",
        "organization": "Agent Auth Demo",
        "endpoint": "http://127.0.0.1:8101/tasks/handle",
        "capabilities": ["ticket-workflow", "publish", "sign", "verify"],
        "keys": [
          {
            "kid": "vault:transit/intake-agent",
            "alg": "ES256",
            "status": "active",
            "public_key_base64url": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE...",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYH...\n-----END PUBLIC KEY-----",
            "not_before": null,
            "not_after": null
          }
        ],
        "revoked_kids": [],
        "updated_at": "2026-06-17T08:00:00.000000Z",
        "environment": "demo",
        "signing_policy": {
          "canonical_request": "v1",
          "signed_message": "v1"
        },
        "verification_policy": {
          "resolve_via": "/.well-known/agent.json"
        },
        "audit": {
          "mode": "jsonl",
          "destination": null
        }
      },
      "published_at": "2026-06-17T08:00:00.000000Z",
      "publisher": null
    },
    {
      "agent_id": "agent://127.0.0.1:8102/triage-agent",
      "metadata": {
        "version": "1.0",
        "agent_id": "agent://127.0.0.1:8102/triage-agent",
        "domain": "127.0.0.1:8102",
        "name": "triage-agent",
        "organization": "Agent Auth Demo",
        "endpoint": "http://127.0.0.1:8102/tasks/handle",
        "capabilities": ["ticket-workflow", "publish", "sign", "verify"],
        "keys": [
          {
            "kid": "vault:transit/triage-agent",
            "alg": "ES256",
            "status": "active",
            "public_key_base64url": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE...",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYH...\n-----END PUBLIC KEY-----",
            "not_before": null,
            "not_after": null
          }
        ],
        "revoked_kids": [],
        "updated_at": "2026-06-17T08:05:00.000000Z",
        "environment": "demo",
        "signing_policy": {
          "canonical_request": "v1",
          "signed_message": "v1"
        },
        "verification_policy": {
          "resolve_via": "/.well-known/agent.json"
        },
        "audit": {
          "mode": "jsonl",
          "destination": null
        }
      },
      "published_at": "2026-06-17T08:05:00.000000Z",
      "publisher": null
    }
  ]
}
```

---

## 七、文档生成与消费

### 生成流程

1. Agent 通过 SDK 调用 `AgentInstance.publish()` → `publish_to_registry()` → `sign_registry_publish_request()` 签名后 POST 到 Registry
2. Registry `app.py` 的 `publish_agent()` 端点**双重验证**：
   - 校验 `Authorization: Bearer {api_key}` 中的 developer API key
   - 使用 metadata 中的公钥验证 Agent 签名（`verify_registry_publish_signature`）
3. 首次 publish 建立 `agent_id → developer_id` owner 绑定
4. `RegistryStore.upsert_agent()` 写入 SQLite（`agent_ownership` + `agent_registry_entries` 表）
5. `RegistryStore.write_public_document()` 调用 `render_public_document()`，从数据库读取所有条目、反序列化 metadata、构造 `AgentRegistryDocument`、写入 JSON 文件

### 消费流程

1. Agent 调用 `resolve_agent(agent_id)`：
   - 若配置了 `registry_url`，优先 GET Registry 聚合文档 → 遍历 `agents[]` 找到匹配 `agent_id` 的条目 → 提取 `metadata`
   - 若 registry 不可用或未配置，fallback 到 `https://{domain}/.well-known/agent.json`
2. `verify_http_request()` / `verify_agent_message()` 通过 `resolve_agent()` 获取 metadata 后：
   - 调用 `select_verification_key(metadata, kid, now)` 从 `keys[]` 中选出匹配 `kid` 且 `status == "active"` 的 key
   - 使用该 key 的 `public_key_pem` 验证签名

### 文件输出路径

Registry 通过环境变量 `AGENT_REGISTRY_PATH` 指定输出路径，默认值：

```
runtime/registry/.well-known/agent.json
```

Registry 同时提供 HTTP 端点 `GET /.well-known/agent.json`，每次访问时实时渲染并落盘。
