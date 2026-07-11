# Agent Auth SDK

`verifiable-agent-auth-sdk` 为 Agent 提供可验证身份、Registry 公钥发现、HTTP/消息签名验签、nonce 防重放和 Vault Transit 私钥托管。`verifiable-agent-auth-registry` 是配套的单节点身份注册服务。

当前版本：`0.2.0b1`（Beta）。Python 3.11–3.13。

## 它解决什么问题

当 Agent A 调用 Agent B 时，B 通常只能相信网络位置或应用传入的字符串。本项目把调用绑定到可验证的 Agent 身份：

```text
Registry 管理员 ──分配 namespace──> Developer
Developer ──发布公钥 metadata──> HTTPS Registry
Agent A ──Vault 私钥签名请求──> Agent B
Agent B ──从 Registry 解析 A 的公钥并验签──> 认证上下文
应用授权策略 ──基于认证上下文决定是否允许调用──> 业务处理
```

认证成功证明发送方持有 Registry 中登记密钥且内容未被篡改；它不自动授予业务权限。

## 安装

```bash
pip install verifiable-agent-auth-sdk

# 按需安装
pip install "verifiable-agent-auth-sdk[vault]"
pip install "verifiable-agent-auth-sdk[redis]"
pip install "verifiable-agent-auth-sdk[openai]"
pip install "verifiable-agent-auth-sdk[openai-fastapi]"

# 部署中心 Registry
pip install verifiable-agent-auth-registry
```

| Extra | 用途 |
|---|---|
| `vault` | HashiCorp Vault Transit signer |
| `redis` | 多进程/多实例原子 nonce store |
| `openai` | OpenAI Agents SDK 显式调用边界 |
| `openai-fastapi` | OpenAI Agents + 声明式 FastAPI 远程 Agent endpoint |

## 从哪里开始

- 有 HTTPS Registry 和 Vault：按 [Quick Start](https://github.com/YiheHuang/agent_auth_sdk/blob/main/QUICKSTART.md) 发布两个 Agent 并完成真实验签。
- 想先在本机理解签名流程：运行 [本地消息示例](https://github.com/YiheHuang/agent_auth_sdk/blob/main/examples/local_signed_message.py)。
- 使用 OpenAI Agents：阅读 [OpenAI Agents 集成](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)。
- 部署 Registry：阅读 [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)。

最常用的应用入口是：

```python
from agent_auth_sdk import AgentVerifier, MetadataResolverConfig

async with AgentVerifier(
    resolver_config=MetadataResolverConfig(
        registry_url="https://registry.example.com",
    ),
) as verifier:
    result = await verifier.verify_message(
        message=incoming_message,
        expected_recipient="agent://agents.example.com/team/receiver",
    )
    if not result.ok:
        raise PermissionError(f"{result.code}: {result.reason}")
```

## 核心能力

- `AgentInstance`：聚合 Agent identity、metadata 和 signer，提供发布、签名和密钥生命周期操作。
- `RegistryClient`：使用 developer credential 发布身份和更新密钥。
- `AgentVerifier`：集中管理 metadata 发现、缓存、nonce 和验签配置。
- `RemoteAgentClient` / `AgentAuthASGIMiddleware`：保护真实 HTTP Agent 边界。
- `AuthorizationPolicy`：在认证之后显式执行应用授权。
- `AuthenticatedOpenAIAgents`：包装 OpenAI `Runner.run` 或生成可用于 `function_tool` 的 authenticated callable。
- `OpenAIAgentAuth`：面向已有 OpenAI Agents 项目的单身份入口，可原样保护 `FunctionTool`、
  `Agent.as_tool()`、handoff 和远程 Tool。
- `AgentAuthRouter`：声明式 FastAPI 接收端，自动验签请求、注入上下文并签名响应。

## 安全边界

- Registry 管理员是 developer namespace 的信任根；v1 不执行 DNS challenge。
- strict profile 要求 HTTPS 和公共 DNS identity，并在 Registry 故障时失败关闭。
- 私钥保留在 Vault Transit；SDK 读取固定 key version 的公钥并请求签名。
- `InMemoryNonceStore` 仅适合单进程；多实例接收端应使用 `RedisNonceStore`。
- OpenAI `call_local_agent()` 不提供进程隔离；跨进程使用签名 HTTP 边界。
- Registry v1 只支持单节点、单 worker SQLite，不支持 HA。
- 自定义协议 v1 不是 RFC 9421 或 JWS。

完整说明见 [安全模型](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md) 和 [协议 v1](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/PROTOCOL_V1.md)。

## 文档

- [Quick Start](https://github.com/YiheHuang/agent_auth_sdk/blob/main/QUICKSTART.md)
- [SDK 使用指南](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SDK_GUIDE.md)
- [公开 API Reference](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/API_REFERENCE.md)
- [Examples](https://github.com/YiheHuang/agent_auth_sdk/tree/main/examples)
- [OpenAI Agents 集成](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)
- [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)
- [安全模型](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)
- [协议 v1](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/PROTOCOL_V1.md)
- [CHANGELOG](https://github.com/YiheHuang/agent_auth_sdk/blob/main/CHANGELOG.md)
- [维护者版本与代码修改清单](https://github.com/YiheHuang/agent_auth_sdk/blob/main/RELEASE.md)

## 开发验证

```bash
python -m pip install -e ".[all,dev]"
python -m pip install -e "packages/agent-auth-registry[dev]"
python -m pytest -q
python -m ruff check agent_auth_sdk packages/agent-auth-registry/src pytests examples
python -m mypy agent_auth_sdk
```

安全问题请按 [SECURITY.md](https://github.com/YiheHuang/agent_auth_sdk/blob/main/SECURITY.md) 私密报告。

## License

MIT
