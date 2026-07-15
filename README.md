# Agent Auth

Agent Auth 为 OpenAI Agents 提供最小的 Agent 身份注册、调用签名和身份验证能力。它不管理模型、提示词、业务授权或工作流。

两个发行包：

- `verifiable-agent-auth-sdk`：应用侧认证，Python import 为 `agent_auth`。
- `verifiable-agent-auth-registry`：单节点 SQLite 中心 Registry。

当前正式版为 `1.0.0`，支持 Python 3.11–3.14 和 `openai-agents>=0.18.2,<0.19`。

## 安装

```bash
pip install "verifiable-agent-auth-sdk[openai]==1.0.0"
# 提供远程 FastAPI endpoint：
pip install "verifiable-agent-auth-sdk[server]==1.0.0"
```

基础 SDK 只有 `cryptography` 与 `httpx` 两个直接依赖。生产 Vault Transit 通过 `httpx` 直接访问。

## 三分钟本地接入

```bash
agent-auth init
agent-auth check
```

```python
from agent_auth import AgentAuth

auth = AgentAuth()
auth.bind({"agent": coordinator})
result = await auth.run(coordinator, "分析这个问题")
```

`auth.run()` 自动认证普通 FunctionTool、`Agent.as_tool()` 和 handoff。dev 模式使用临时内存 key；production 使用固定版本 Vault key。

远程 Agent：

```python
research_tool = auth.remote_tool(
    "researcher",
    input_type=ResearchRequest,
    output_type=ResearchResult,
)
```

```python
@auth.endpoint("/invoke", identity="researcher", request=ResearchRequest, response=ResearchResult)
async def invoke(ctx, request):
    return ResearchResult(summary=f"request from {ctx.sender}")

app.include_router(auth.router)
```

## 安全边界

- 本地和远程 Agent 调用使用同一种 SignedEnvelope，并执行请求与结果签名验签。
- 同进程认证不提供私钥或代码隔离；同一进程能访问它加载的全部 Vault token。
- production 只从中心 Registry 解析身份，不回退到 Agent 声明的任意 URL。
- Registry namespace 由管理员分配；v1 不实现 DNS challenge。
- capability 是签名声明，不等于业务授权。handler 使用 `AuthContext` 自行授权。
- Registry 和 SDK production state 均为单节点 SQLite，不宣称 HA。

## 文档

- [Quick Start](https://github.com/YiheHuang/agent_auth_sdk/blob/main/QUICKSTART.md)
- [API](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/API_REFERENCE.md)
- [OpenAI Agents](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)
- [Protocol v1](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/PROTOCOL_V1.md)
- [Security](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)
- [Registry 运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)
- [Examples](https://github.com/YiheHuang/agent_auth_sdk/tree/main/examples)

License: MIT
