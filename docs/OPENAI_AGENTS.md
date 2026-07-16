# OpenAI Agents 集成

OpenAI Agents 是 Agent Auth 1.0 的核心支持框架。支持范围为 `openai-agents>=0.18.2,<0.19`。

## 已有项目接入

原代码：

```python
result = await Runner.run(coordinator, input)
```

接入后：

```python
auth = AgentAuth().bind({"coordinator": coordinator, "researcher": researcher})
async with auth:
    result = await auth.run(coordinator, input)
```

Agent Auth 不修改全局 Runner。每次 `auth.run` 都会幂等扫描已绑定 Agent 当前的 tools/handoffs：

- FunctionTool：签名并验证调用方执行事件。
- Agent.as_tool：请求与结果由双方身份分别签名验签。
- handoff：签名并验证身份转移；handoff 本身没有返回 envelope。
- 并行或嵌套工具：每次调用生成独立 request ID。

未绑定的 Agent-as-tool 或 handoff target 在模型运行前失败。动态业务代码中的显式嵌套 Runner 也必须改为 `auth.run`。

普通 FunctionTool 没有独立 Agent 身份；SDK 认证的是调用 Agent 对该工具的执行事件。Agent-as-tool 才由调用方和目标 Agent 分别签署请求与结果。

## Streaming 和 Session

```python
async with auth:
    streamed = auth.run_streamed(coordinator, input, session=session)
    async for event in streamed.stream_events():
        ...
```

模型 token 不逐块签名；流中发生的 Agent tool/handoff 边界仍逐次认证。`run`、`run_sync` 和 `run_streamed` 保持 OpenAI 的返回对象。

## 远程 Agent

`[remotes]` 只保存 Agent ID。SDK 从 Registry 获取并校验 endpoint：

```python
tool = auth.remote_tool("researcher", input_type=Request, output_type=Result)
coordinator.tools.append(tool)
```

服务端使用 `@auth.endpoint`；handler 不接触 envelope、signature、nonce 或 Registry resolver。成功响应自动由服务身份签名。

同进程认证与远程认证使用同一协议，但同进程不能阻止该进程读取它已加载的其他身份 token。

服务端 handler 根据 `AuthContext` 做业务授权。认证失败由 SDK 映射为稳定 JSON 错误，handler 不接触 envelope、signature 或 nonce。
