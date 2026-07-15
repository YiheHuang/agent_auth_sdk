# API Reference

正式公开面只有 `AgentAuth`、`AuthContext`、`AgentAuthError` 和 `__version__`。

## AgentAuth

```python
AgentAuth(config: str | Path | None = None)
```

配置优先级：显式路径、`AGENT_AUTH_CONFIG`、当前目录 `agent-auth.toml`。

- `bind(mapping) -> AgentAuth`：`{配置 alias: OpenAI Agent}`。对象或 alias 重复绑定会失败。
- `await run(agent, input, **runner_options)`：认证 Agent 图后调用 `Runner.run`，原样返回 `RunResult`。
- `run_sync(...)`：同步等价入口；活跃 event loop 中拒绝。
- `run_streamed(...)`：返回原生 `RunResultStreaming`；必须先进入 AgentAuth context。
- `remote_tool(alias, *, input_type, output_type, name=None, description=None)`：返回原生 `FunctionTool`。
- `endpoint(path, *, identity, request, response)`：FastAPI handler decorator。
- `router`：传给 `app.include_router()` 的原生 `APIRouter`。
- `close()`、同步/异步 context manager：管理 Vault、Registry 和 HTTP 资源。

`run` 会原样传递 OpenAI Runner 参数，包括 context、max_turns、hooks、run_config、session、conversation 和 response ID 参数。

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

只代表已经完成的身份认证。业务代码必须自行决定 sender/capability 是否有权执行操作。

## AgentAuthError

所有公开失败统一抛出：

```python
except AgentAuthError as exc:
    logger.warning("agent auth failed", extra=exc.as_dict())
```

字段：`code`、安全 message、可选 request_id、agent_id 和不含秘密的 details。SDK 不公开异常子类。
