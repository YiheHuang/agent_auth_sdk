# OpenAI Agents 集成

## 两种边界

### 同进程

`call_local_agent()` 在显式 `Runner.run` 边界签名并验证请求/结果，适合审计编排流程。调用方和目标 signer 位于同一 Python runtime，因此它不提供进程隔离。
非字符串 payload 在交给真实 `Runner.run` 前会编码为确定性 JSON 字符串；自定义 runner 仍收到原始 Python payload。

```python
result = await auth.call_local_agent(
    source_role="coordinator",
    target_role="security",
    target_agent=security,
    payload=payload,
    runner=Runner.run,
)
```

旧 `call_agent()` 暂时委托给 `call_local_agent()`。

### 远程 HTTP

`call_remote_agent()` 使用 source Agent 签名实际 HTTP body，并要求目标返回 target Agent 签名且 recipient 指向 source 的消息。

```python
result = await auth.call_remote_agent(
    source_role="coordinator",
    target_agent_id="agent://agents.example.com/security",
    target_url="https://agents.example.com/security/invoke",
    payload=payload,
)
```

接收端使用 `AgentAuthASGIMiddleware`，业务 handler 从 `scope["state"]["agent_auth"]` 或框架对应 request state 读取认证上下文，并用 `sign_remote_result()` 返回签名结果。

## Tool factory

- `wrap_tool()`：生成同进程 callable。
- `wrap_remote_tool()`：生成可交给 `function_tool` 的远程 callable。

## 兼容策略

集成只依赖 OpenAI Agents 的公开 `Agent`、`Runner.run` 和 `function_tool` 调用方式，不做 monkey patch。CI 应同时测试声明范围内最低和最新 `openai-agents` 版本。
