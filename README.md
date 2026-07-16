# Agent Auth

Agent Auth 为 Agent 提供最小的身份注册、调用签名与身份验证能力。它不管理模型、提示词、工作流或业务授权。

- `verifiable-agent-auth-sdk`：应用侧 SDK，Python import 为 `agent_auth`。
- `verifiable-agent-auth-registry`：单节点 SQLite 身份 Registry。

当前版本 `1.1.0`，支持 Python 3.11–3.14；OpenAI Agents 支持范围为 `>=0.18.2,<0.19`。

## 安装

```bash
pip install "verifiable-agent-auth-sdk==1.1.0"
pip install "verifiable-agent-auth-sdk[openai]==1.1.0"  # OpenAI Agents
pip install "verifiable-agent-auth-sdk[server]==1.1.0"  # OpenAI Agents + FastAPI endpoint
```

基础 SDK 只有 `cryptography` 和 `httpx` 两个直接依赖。

## 最短用法

```python
from agent_auth import AgentAuth

async with AgentAuth() as auth:  # 读取 agent-auth.toml
    result = await auth.call("coordinator", "researcher", {"query": "分析这个问题"})
```

已有 OpenAI Agents 项目只需绑定身份并替换 Runner 入口：

```python
auth = AgentAuth().bind({"coordinator": coordinator, "researcher": researcher})
async with auth:
    result = await auth.run(coordinator, "分析这个问题")
```

`auth.run()` 会认证 FunctionTool 执行事件、`Agent.as_tool()` 与 handoff；远程边界使用 `remote_tool()` 和 `endpoint()`。

## 运行模式

| mode | 密钥与 nonce | 服务地址 | 用途 |
|---|---|---|---|
| `dev` | 临时内存 key/nonce | 允许开发地址 | 无基础设施测试 |
| `local` | Vault + SQLite | 仅 loopback | 本机真实集成 |
| `production` | Vault + SQLite | 公网 HTTPS | 生产部署 |

## 安全边界

- 所有 Agent 边界使用同一 SignedEnvelope v1，并校验 audience、timestamp、nonce 和响应关联。
- 同进程认证不提供进程级私钥隔离；生产建议一进程一身份。
- production 只信任中心 Registry，且不回退到任意 well-known URL。
- capability 是经过签名的声明，不等于授权；handler 必须根据 `AuthContext` 决策。
- Registry v1 是单节点、单 worker 服务，不支持 HA。

## 文档

- [Quick Start](https://github.com/YiheHuang/agent_auth_sdk/blob/main/QUICKSTART.md)
- [配置](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/CONFIGURATION.md)
- [API](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/API_REFERENCE.md)
- [OpenAI Agents](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)
- [Protocol v1](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/PROTOCOL_V1.md)
- [安全模型](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)
- [Registry 运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)
- [示例](https://github.com/YiheHuang/agent_auth_sdk/tree/main/examples)

License: MIT
