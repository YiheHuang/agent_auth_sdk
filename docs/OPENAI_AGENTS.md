# OpenAI Agents SDK 集成

`1.0.0rc1` 面向已有 OpenAI Agents 项目提供原生 Tool、Agent-as-tool、handoff 和远程 HTTP
边界。SDK 不 monkey patch `Agent` 或 `Runner`，只包装开发者明确选中的跨 Agent 边界。

```bash
pip install "verifiable-agent-auth-sdk[openai]==1.0.0rc1"
# 使用声明式 FastAPI 接收端时：
pip install "verifiable-agent-auth-sdk[openai-fastapi]==1.0.0rc1"
```

正式支持 `openai-agents >=0.18.2,<0.19`，CI 验证最低版本和该 minor 的最新版本。

## 已有项目五分钟接入

假设项目已经有 coordinator 和 security Agent：

```python
from agents import Agent, Runner
from agent_auth_sdk.openai import OpenAIAgentAuth

coordinator = Agent(name="coordinator", instructions="Use the security tool.")
security = Agent(name="security", instructions="Review the input.")

auth = await OpenAIAgentAuth.from_env()
auth.bind({"security": security})
security_tool = auth.agent_as_tool(
    security,
    tool_name="security_review",
    tool_description="Run an authenticated security review.",
)
coordinator.tools.append(security_tool)
result = await Runner.run(coordinator, "Review this configuration")
```

OpenAI `Agent` 是不可哈希 dataclass，因此 `bind()` 使用 `{role: agent}`，而不是把 Agent
对象作为 dict key。也可以传 `[(security, "security")]`。

local mode 会为配置中的 role 创建临时 P-256 key 和内存 Registry，只用于开发、测试和
同进程审计。它不能阻止同一进程中的代码访问 signer。

## 包装已有 FunctionTool

已有 `@function_tool` 不需要重写：

```python
protected = auth.protect_tool(
    existing_tool,
    target="security",  # 也可传完整 agent:// ID
)
```

返回值仍是原来的 `FunctionTool` 类型，并保留 name、description、参数 JSON Schema、
`is_enabled`、strict schema 以及当前 OpenAI Agents 版本增加的其他 dataclass 字段。

## Handoff

```python
security_handoff = auth.authenticated_handoff(
    security,
    identity="security",
    tool_name="transfer_to_security",
)
```

同进程 handoff 只提供签名审计和应用授权，不提供进程隔离。跨服务调用使用下一节的
`remote_agent_tool()`。

## 生产环境：一个进程一个身份

运行时只加载当前服务的 signer，不自动创建 Vault key，也不自动发布身份：

```python
auth = await OpenAIAgentAuth.from_env()
async with auth:
    ...
```

首次部署或明确更新 metadata 时单独执行：

```bash
agent-auth provision --config .agent-auth/agent-auth.toml
```

生产 TOML 应设置 `profile = "strict"`、`mode = "vault"`、`auto_create_keys = false`。
如果需要首次创建 Vault key，管理员可在受控 provisioning 环境暂时设为 `true`；应用
运行 token 不应拥有创建 key 的权限。

strict profile 禁止通过 `AGENT_AUTH_ENABLED=0` 绕过认证。

## 声明式远程 Tool

客户端声明输入输出模型，得到可直接放入 `Agent.tools` 的 `FunctionTool`：

```python
from pydantic import BaseModel

class SecurityRequest(BaseModel):
    prompt: str

class SecurityResult(BaseModel):
    answer: str

security_tool = auth.remote_tool(
    "security",
    description="Call the authenticated security service.",
    input_type=SecurityRequest,
    output_type=SecurityResult,
)
```

目标身份和 URL 在配置中只写一次：

```toml
[remotes.security]
agent_id = "agent://agents.example.com/security"
url = "https://security.example.com/invoke"
```

SDK 对实际 JSON body bytes 签名，并要求响应 sender、recipient、message type 和签名全部匹配。

服务端安装 `openai-fastapi` extra：

```python
from agent_auth_sdk.openai import AuthenticatedAgentContext

router = auth.router()

@router.endpoint("/invoke", request_model=SecurityRequest)
async def invoke(
    ctx: AuthenticatedAgentContext,
    request: SecurityRequest,
) -> SecurityResult:
    result = await Runner.run(security, request.prompt, context=ctx)
    return SecurityResult(answer=str(result.final_output))

app.include_router(router)
```

Router 自动完成原始 body 验签、认证上下文注入、授权策略、稳定错误映射和响应签名。
`authenticated_agent` 还可作为 `Depends()` 依赖读取 middleware 已写入的上下文。

完整双进程示例见
[`examples/openai_agents/remote_server.py`](../examples/openai_agents/remote_server.py) 和
[`remote_client.py`](../examples/openai_agents/remote_client.py)。

## 认证与授权

认证成功只证明 sender 持有 Registry 中登记的私钥。业务权限通过 `AuthorizationPolicy`
显式决定，并在创建 `OpenAIAgentAuth` 时传入。`AuthenticatedAgentContext` 提供：

- `agent_id`、`kid`、`capabilities`、`request_id`；
- `has_capability()`；
- FastAPI state、OpenAI run context 和普通应用代码的统一表示。

稳定异常包括 `AgentAuthenticationError`、`AgentAuthorizationError`、`AgentReplayError`、
`AgentDiscoveryError`、`AgentTransportError` 和 `AgentConfigurationError`。异常字符串不包含
payload、token、私钥或完整签名。

## 检查已有项目

```bash
# 只读扫描 Agent、FunctionTool、Agent.as_tool、handoff、Runner 和 FastAPI endpoint
agent-auth openai inspect .
agent-auth openai inspect . --json

# 默认仍为 dry run
agent-auth openai migrate .

# 幂等写入 .agent-auth/OPENAI_MIGRATION.md 和机器可读 JSON
agent-auth openai migrate . --write
```

身份和授权策略不能从 Python 语法安全推断，所以 migrate 不直接改写业务源码；它生成精确到
文件和行号的迁移清单，避免产生身份错误的自动 codemod。

## 事件与诊断

`auth.events()` 返回不含 payload/凭证、最多 1000 条的 `AgentAuthEvent`；`drain_events()`
读取后清空。创建 facade 时可以传入同步或异步
`event_sink`，接入应用日志、metrics 或 tracing exporter。事件包含 operation、source、target、
结果、稳定错误码、耗时和 request ID。

## 兼容接口

`AuthenticatedOpenAIAgents`、`call_local_agent()`、`wrap_tool()` 和 `call_remote_agent()` 在
在 1.x 中继续工作，但标记为兼容层。新代码使用 `OpenAIAgentAuth`。兼容层仍可用于旧项目
渐进迁移；其 multi-role Vault runtime 不应作为新的生产部署模型。

官方概念参考：[Tools](https://openai.github.io/openai-agents-python/tools/)、
[Handoffs](https://openai.github.io/openai-agents-python/handoffs/)、
[Context](https://openai.github.io/openai-agents-python/context/)。
