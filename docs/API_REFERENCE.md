# 公开 API Reference

本文记录 `0.2.0b1` 承诺支持的公开接口。优先从 `agent_auth_sdk` 顶层导入；OpenAI 适配从 `agent_auth_sdk.integrations` 导入。

未列出的 `registry_security`、`http_utils` canonical helper、`publish` 底层请求函数和以下划线开头的符号属于内部实现。协议实现者应依据 [协议 v1](PROTOCOL_V1.md)，而不是复制内部函数。

`agent_auth_sdk.__version__` 返回当前发行版本字符串。

## AgentInstance

```python
from agent_auth_sdk import AgentInstance
```

| 接口 | 作用 / 关键参数 | 返回 |
|---|---|---|
| `AgentInstance.from_vault(...)` | `domain`, `name`, `endpoint`, Vault 地址/token 文件/mount/key；可选 capability、namespace、CA、kid | 固定 Vault key version 的 `AgentInstance` |
| `AgentInstance.from_signer(...)` | 自定义 `Signer`、P-256 public PEM、kid 和 metadata 字段 | `AgentInstance` |
| `signer` | 当前 `Signer`；没有 signer 时抛 `ValueError` | `Signer` |
| `export_metadata(output_dir)` | 导出 `/.well-known/agent.json` | 写入的 `Path` |
| `publish(...)` | 向完整 publish endpoint 发布 metadata | Registry JSON dict |
| `sign_http(...)` | 签 method、URL、实际 body bytes 和 headers | `SignatureHeaders` |
| `sign_message(...)` | 签 payload，可绑定 recipient/message_type | `SignedAgentMessage` |
| `add_key(...)` | Vault `new_key_name` 或外部新 signer 三元组 | Registry JSON dict |
| `rotate_key(...)` | 切换 current signer，并同步本地 metadata | Registry JSON dict |
| `revoke_key(...)` | 撤销非 current、非最后 active key | Registry JSON dict |
| `revoke_agent(...)` | 不可逆撤销 Agent | Registry JSON dict |

所有网络方法为 async。Vault 创建是同步构造，async 应用可用 `asyncio.to_thread(AgentInstance.from_vault, ...)`。

## RegistryClient

```python
RegistryClient(
    *, base_url: str, client_id: str,
    api_key: str | Callable[[], str | Awaitable[str]],
    http_client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
    allow_insecure_http: bool = False,
)
```

实现 async context manager。`base_url` 默认必须 HTTPS；`allow_insecure_http` 仅用于隔离的 loopback 测试。

| 方法 | 关键参数 |
|---|---|
| `publish(metadata, signer=...)` | 首次注册或同 owner 更新 metadata |
| `rotate_key(agent_id, new_key, current_signer, new_signer)` | current proof + new-key proof |
| `add_key(agent_id, new_key, current_signer, new_signer)` | 添加额外 active key |
| `revoke_key(agent_id, kid_to_revoke, current_signer)` | 永久撤销 kid |
| `revoke_agent(agent_id, current_signer)` | 撤销整个 Agent |

HTTP 非 2xx 会通过 `httpx.Response.raise_for_status()` 抛出。

## AgentVerifier 与 AuthorizationPolicy

```python
AgentVerifier(
    *, nonce_store: NonceStore | None = None,
    cache: MetadataCache | None = None,
    verification_config: VerificationConfig | None = None,
    resolver_config: MetadataResolverConfig | None = None,
    http_client: httpx.AsyncClient | None = None,
)
```

实现 async context manager。未传 store/cache 时使用单进程内存实现。

| 方法 | 返回 |
|---|---|
| `verify_http(method, url, headers, body, request_id=None)` | `VerificationSuccess | VerificationFailure` |
| `verify_message(message, expected_recipient=None)` | `VerificationSuccess | VerificationFailure` |
| `authorize(result, policy, capability=None)` | 原 success 或 `POLICY_REJECTED` failure |

`AuthorizationPolicy`：

```python
class AuthorizationPolicy(Protocol):
    async def authorize(
        self, result: VerificationSuccess, *, capability: str | None = None
    ) -> bool: ...
```

## RemoteAgentClient 与 AgentAuthASGIMiddleware

```python
RemoteAgentClient(*, sender: AgentInstance, verifier: AgentVerifier, http_client=None)
```

`await call(target_url, target_agent_id, payload, message_type="agent.call.result")` 对 canonical JSON bytes 签名、POST，并要求响应是由 `target_agent_id` 签发且 recipient 为 sender 的 `SignedAgentMessage`。认证失败抛 `PermissionError`。

```python
AgentAuthASGIMiddleware(app, *, verifier: AgentVerifier, max_body_bytes=1_048_576)
```

HTTP 验签失败返回 401 JSON；body 过大返回 413；成功时写入 ASGI `scope["state"]["agent_auth"]`。WebSocket 等非 HTTP scope 原样传递。

## 配置与 Profile

| 名称 | 字段 / 行为 |
|---|---|
| `RuntimeProfile` | `allow_http`, `allow_ip_host`, clock skew、cache TTL、nonce TTL |
| `STRICT_PROFILE` | HTTPS、拒绝 IP identity、120 秒时钟偏差 |
| `TEST_PROFILE` | 允许 HTTP/IP，仅用于测试 |
| `SigningConfig` | `profile`, `include_signature_input_header` |
| `VerificationConfig` | `profile`, `require_signature_input_header` |
| `DiscoveryMode` | `REGISTRY_ONLY`, `DIRECT_ONLY`, `REGISTRY_THEN_DIRECT` |
| `MetadataResolverConfig` | profile、cache TTL、timeout、`registry_url`、discovery mode |

配置 Registry 后，`MetadataResolverConfig.effective_discovery_mode` 默认为 `REGISTRY_ONLY`。

## Signer、Vault 与身份

`Signer` Protocol：

```python
async def kid() -> str
async def algorithm() -> str
async def sign(data: bytes) -> bytes
```

v1 仅支持返回 ASN.1 DER ECDSA signature 的 `ES256` signer。`CallableSigner` 把 async callable 适配为 `Signer`。

| Vault API | 作用 |
|---|---|
| `VaultKmsConfig` | Vault 地址、mount、key、token file、namespace、TLS、固定 version/kid |
| `VaultTransitPublicKeyResolver.describe()` | 返回 public PEM、latest version、kid 信息 |
| `VaultTransitSigner` | 固定 key version 的 async signer；阻塞 Vault sign 在线程执行 |

身份辅助：

- `build_agent_id(host, agent_name) -> str`
- `parse_agent_id(agent_id) -> ParsedAgentId`
- `AgentIdentityError`：identity 输入错误。
- `MetadataValidationError`：metadata/发现结果错误。

## NonceStore 与 MetadataCache

```python
class NonceStore(Protocol):
    async def consume(self, key: str, ttl_seconds: int) -> bool: ...

class MetadataCache(Protocol):
    async def get(self, agent_id: str) -> ResolveResult | None: ...
    async def set(self, agent_id: str, result: ResolveResult, ttl_seconds: int) -> None: ...
```

实现：`InMemoryNonceStore`、`RedisNonceStore`、`InMemoryMetadataCache`、`FileMetadataCache`。Redis 依赖 `verifiable-agent-auth-sdk[redis]`。

## 协议模型

模型使用 Pydantic，未知字段默认拒绝，扩展写入 `extensions`。

| 模型 | 主要字段 |
|---|---|
| `AgentAuditConfig` | mode、destination、extensions |
| `AgentKey` | kid、ES256 key material、status、有效期 |
| `AgentMetadata` | identity、organization、endpoint、capabilities、keys、revoked kids |
| `SignedAgentMessage` | sender、kid、UTC timestamp、nonce、payload、recipient、message_type、signature |
| `AgentRegistryEntry` | agent_id、metadata、published_at、publisher |
| `AgentRegistryDocument` | 聚合 `/.well-known/agent.json` |
| `ParsedAgentId` | raw、host、agent_name、path_segments |

结果类型：

- `ResolveResult`：metadata、resolved_at、etag、source_url。
- `SignatureHeaders`：`headers`、canonical string、body digest。
- `VerificationSuccess`：`ok=True`、agent_id、kid、metadata，可选 request_id/message。
- `VerificationFailure`：`ok=False`、稳定 `code` 和适合日志的 `reason`。

`VerificationErrorCode` 包含：`INVALID_AGENT_ID`、`INVALID_METADATA`、`MESSAGE_INVALID`、`METADATA_FETCH_FAILED`、`METADATA_HOST_MISMATCH`、`KEY_NOT_FOUND`、`KEY_REVOKED`、`KEY_EXPIRED`、`SIGNATURE_INVALID`、`TIMESTAMP_EXPIRED`、`NONCE_REPLAYED`、`POLICY_REJECTED`、`RECIPIENT_MISMATCH`。

## 低级签名、验签和发现

以下入口适合框架集成；普通应用优先使用 `AgentInstance` 和 `AgentVerifier`：

- `resolve_agent(agent_id, *, profile, http_client, cache=None, config=None) -> ResolveResult`
- `verify_http_request(...) -> VerificationSuccess | VerificationFailure`
- `verify_agent_message(...) -> VerificationSuccess | VerificationFailure`
- `agent_auth_sdk.signing.sign_http_request()` / `sign_http_request_sync()`
- `agent_auth_sdk.messaging.sign_agent_message()` / `sign_agent_message_sync()`
- `agent_auth_sdk.messaging.verify_agent_message_sync()`
- `agent_auth_sdk.verification.verify_http_request_sync()`

sync wrapper 内部使用 `asyncio.run()`，不能在已经运行的 event loop 中调用。

## OpenAI Agents API

新接口可从 `agent_auth_sdk` 顶层或 `agent_auth_sdk.integrations` 导入。

### OpenAIAgentAuth

- `await OpenAIAgentAuth.from_env(identity, config_path=...)`：加载单个运行身份，不创建 key、不发布。
- `from_env_sync(...)`：无活动 event loop 时的同步构造入口。
- `await from_config(config, identity=..., provision=False)`：从已解析配置构造。
- `from_components(...)`：依赖注入入口，适合测试或自定义 KMS。
- `local(identity, domain=...)`：单身份本地构造器；不支持本地跨 role Tool。
- `await provision()` / `provision_sync()`：显式发布当前 metadata。
- `bind({role: agent})`：绑定 OpenAI Agent 对象；也接受 `[(agent, role)]`。
- `protect_tool(tool, target=...)`：保护已有 `FunctionTool` 并保留 dataclass 字段。
- `agent_as_tool(agent, identity=..., ...)`：创建受保护的原生 Agent-as-tool。
- `remote_agent_tool(...)`：由 Pydantic 输入输出类型创建签名远程 `FunctionTool`。
- `remote_agent_tools(specs)`：按顺序批量创建 `RemoteAgentToolSpec` 声明的远程 tools。
- `authenticated_handoff(...)`：同进程签名审计/授权 handoff。
- `authenticated_context(result)`：将验签成功结果转换为 `AuthenticatedAgentContext`。
- `events()`：返回当前进程的 `AgentAuthEvent` 副本。
- 支持 `async with`；退出时关闭 facade 拥有的 HTTP client。

`AuthenticatedTool` 是框架无关的最小 Tool Protocol；`RemoteAgentToolSpec` 是不可变的批量远程
Tool 配置。

### AgentAuthRouter 与 authenticated_agent

安装 `openai-fastapi` extra。`AgentAuthRouter(auth).agent_endpoint(...)` 注册 FastAPI 路由，
自动完成请求验签、可选 `AuthorizationPolicy`、`AuthenticatedAgentContext` 注入和响应签名。
`authenticated_agent(request)` 可用于 `Depends()` 读取现有认证上下文。

### AuthenticatedAgentContext

字段：`agent_id`、`kid`、`capabilities`、`request_id`、`authenticated_at`、`extensions`。
`has_capability(name)` 检查声明；`authenticated_context_from(value)` 可从 context、request 或 state 读取。

### AgentAuthEvent 与 EventSink

`AgentAuthEvent` 记录 operation、source/target ID、结果、耗时、错误码和 request ID；不记录 payload
或凭证。`EventSink` 是同步或异步事件回调类型。

### 稳定异常

- `AgentAuthError`：基础异常，提供 `code`、`agent_id`、`request_id`、安全 `details` 和 `as_dict()`。
- `AgentAuthenticationError`、`AgentAuthorizationError`、`AgentReplayError`。
- `AgentDiscoveryError`、`AgentTransportError`、`AgentConfigurationError`。

兼容接口从 `agent_auth_sdk.integrations.openai_agents` 导入：

### OpenAIAgentsAuthConfig

配置 roles、`local|vault` mode、identity domain、runtime dir、capability map、Registry 和 Vault。`from_file(path)` 读取 TOML 并展开环境变量；`capability_for(role)` 返回声明；`registry_document_url()` 返回发现 URL。

### OpenAIAgentsAuthRuntime

- `await create(config)`：创建 local ephemeral agents，或创建 Vault agents 并发布。
- `agent(role)`：获取 role 的 `AgentInstance`。
- `sign_for_role(...)` / `verify_for_role(...)`：role 间消息边界。
- `registry_document()`：local mode 内存 Registry 文档。

### AuthenticatedOpenAIAgents

- `from_config()` / `from_config_file()`：异步工厂。
- `is_enabled()`：读取实例值或 `AGENT_AUTH_ENABLED`。
- `call_local_agent(...)`：在显式 `Runner.run` 边界签名请求和结果。
- `call_agent(...)`：兼容别名；新代码使用 `call_local_agent()`。
- `wrap_tool(...)`：返回可交给 `function_tool` 的 local callable。
- `call_remote_agent(...)` / `wrap_remote_tool(...)`：签名 HTTP 远程边界。
- `sign_remote_result(...)`：接收端签名响应。
- `maybe_authenticate_tools(...)`：按开关选择 authenticated 或 fallback tools。
- `trusted_events()`：返回当前进程记录的成功边界事件。

详见 [OpenAI Agents 集成](OPENAI_AGENTS.md)。

## CLI 与 Registry HTTP API

- `agent-auth init`：必需 `--project-root`、`--roles`；可选 `--framework openai-agents`、`--mode local|vault`、`--domain`、`--organization`。
- `agent-auth integrate-openai-agents`：同上，并支持 `--registry-url`、`--registry-publish-url` 和可重复的 `--role-capability role:capability`。
- `agent-auth doctor --config PATH`：只读检查 TOML、identity、profile、TLS 和 Vault token 文件；默认 `.agent-auth/agent-auth.toml`。
- `agent-auth provision --identity ROLE --config PATH`：显式创建/检查单个 Vault key 并发布身份。
- `agent-auth openai inspect PATH [--json]`：只读 AST 扫描已有 OpenAI Agents 项目。
- `agent-auth openai migrate PATH [--write]`：预览或幂等生成迁移报告；不猜测身份、不改业务源码。
- `agent-auth-registry`、`agent-auth-registry-admin` 和所有 Registry HTTP endpoint：见 [Registry 部署与运维](REGISTRY_OPERATIONS.md)。
