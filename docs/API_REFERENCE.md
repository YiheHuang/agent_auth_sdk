# API Reference

正式公开面只有 `AgentAuth`、`AuthContext`、`AgentAuthError` 和 `__version__`。下划线模块均为内部实现。

`__version__` 是已安装 SDK 的版本字符串。

## AgentAuth

```python
AgentAuth(config: str | Path | None = None)
```

配置优先级为显式路径、`AGENT_AUTH_CONFIG`、当前目录 `agent-auth.toml`。

### 框架无关调用

```python
await call(source: str, target: str, payload: JSONValue) -> JSONValue
```

`source` 必须来自 `[agents]`；`target` 可来自 `[agents]` 或 `[remotes]`。payload 必须是严格 JSON，或可转换为严格 JSON 的 dataclass/Pydantic model。返回值已经完成签名、audience、nonce、timestamp 和 reply correlation 校验。

### OpenAI Agents

- `bind(mapping) -> AgentAuth`：绑定 `{配置 alias: Agent}`；重复或未知绑定失败。
- `await run(agent, input, **runner_options) -> RunResult`：认证 Agent 图后委托 `Runner.run`。
- `run_sync(...) -> RunResult`：同步入口；活跃 event loop 中拒绝。
- `run_streamed(...) -> RunResultStreaming`：必须先进入 async context；完整消费事件后运行才结束。
- `remote_tool(alias, *, input_type, output_type, name=None, description=None) -> FunctionTool`：创建带双向认证和 Pydantic 转换的远程工具。

Runner 参数和返回对象保持原样，包括 context、max_turns、hooks、run_config、session、conversation 和 response ID。

### FastAPI endpoint

```python
@auth.endpoint("/invoke", identity="researcher", request=Request, response=Response)
async def invoke(ctx: AuthContext, request: Request) -> Response:
    ...

app.include_router(auth.router)
```

- `endpoint(...)` 注册只接受 SignedEnvelope 的 POST route，请求上限 1 MiB。
- `router` 返回原生 `APIRouter`。
- handler 必须根据 `ctx.sender` 和 `ctx.capabilities` 自行授权。

### 生命周期

- `await close()` 关闭 Vault、Registry 和 HTTP client。
- `async with AgentAuth() as auth` 是异步服务推荐方式。
- 同步 context 适用于 `run_sync()`；`run_streamed()` 必须使用已启动的 async context。

## AuthContext

```python
AuthContext(
    sender: str,
    kid: str,
    capabilities: tuple[str, ...],
    request_id: str,
    call_type: str,
)
```

它只表示一次已经通过密码学验证的调用。capability 是声明，不是授权结果。

## AgentAuthError

所有公开失败统一抛出 `AgentAuthError`：

```python
except AgentAuthError as exc:
    logger.warning("agent auth failed", extra=exc.as_dict())
```

字段包括稳定 `code`、安全 message、可选 `request_id`、`agent_id` 和不含秘密的 `details`。SDK 不公开异常子类，也不会在异常中放入 token、私钥或完整签名。

### 稳定错误码

| 类别 | code |
|---|---|
| 配置 | `CONFIG_NOT_FOUND`、`CONFIG_INVALID`、`CONFIG_ENV_MISSING`、`CONFIG_EXISTS`、`CONFIG_UPDATE_FAILED` |
| 身份/绑定 | `INVALID_AGENT_ID`、`INVALID_ENDPOINT`、`INVALID_URL`、`INVALID_LOCAL_URL`、`INVALID_LOCAL_IDENTITY`、`INVALID_LOCAL_ENDPOINT`、`IDENTITY_NOT_CONFIGURED`、`IDENTITY_ALREADY_BOUND`、`AGENT_ALREADY_BOUND`、`CALLER_IDENTITY_UNKNOWN`、`UNBOUND_TARGET_AGENT`、`UNBOUND_HANDOFF_TARGET` |
| 生命周期/可选依赖 | `AUTH_NOT_STARTED`、`SYNC_IN_ASYNC_CONTEXT`、`OPENAI_NOT_INSTALLED`、`SERVER_NOT_INSTALLED` |
| Registry/发现 | `REGISTRY_UNAVAILABLE`、`REGISTRY_CREDENTIALS_MISSING`、`REGISTRY_SUBJECT_MISMATCH`、`AGENT_NOT_FOUND`、`INVALID_METADATA`、`ENDPOINT_DNS_FAILED`、`ENDPOINT_NOT_PUBLIC`、`REGISTRY_HTTP_<status>` |
| Vault | `VAULT_CONFIG_INVALID`、`VAULT_TOKEN_MISSING`、`VAULT_TOKEN_UNREADABLE`、`VAULT_TOKEN_EMPTY`、`VAULT_TOKEN_PERMISSIONS`、`VAULT_NOT_READY`、`VAULT_KEY_VERSION_NOT_FOUND`、`VAULT_REQUEST_FAILED`、`VAULT_RESPONSE_INVALID`、`ROTATE_REQUIRES_VAULT` |
| 协议 | `ENVELOPE_INVALID`、`SIGNER_MISMATCH`、`SIGNATURE_INVALID`、`AUDIENCE_MISMATCH`、`TYPE_MISMATCH`、`REPLY_MISMATCH`、`TIMESTAMP_INVALID`、`TIMESTAMP_EXPIRED`、`NONCE_REPLAYED`、`PAYLOAD_INVALID`、`BASE64_INVALID`、`PUBLIC_KEY_INVALID` |
| endpoint/远程调用 | `REQUEST_TOO_LARGE`、`REQUEST_INVALID`、`SCHEMA_INVALID`、`CAPABILITY_DENIED`、`REMOTE_NOT_CONFIGURED`、`REMOTE_CALL_FAILED`、`REMOTE_REJECTED`；远端也可原样返回其稳定 code |

FastAPI endpoint 将 schema 错误映射为 422，业务 capability 拒绝映射为 403，重放映射为 409，Registry/身份不可用映射为 503，畸形请求映射为 400，其余认证失败映射为 401。handler 可直接抛出 `AgentAuthError("CAPABILITY_DENIED", "...")`。
