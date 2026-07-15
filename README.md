# Agent Auth

Agent Auth 是一个轻量的 Python 身份认证组件，只负责三件事：注册 Agent 公钥、为 Agent 调用签名、验证调用方身份。

它由两个独立包组成：

- `verifiable-agent-auth-sdk`：在应用中签名、验签，并适配 OpenAI Agents。
- `verifiable-agent-auth-registry`：保存 developer namespace 和 Agent 公钥的单节点 Registry。

当前候选正式版为 `1.0.0rc1`，支持 Python 3.11–3.14。wire protocol v1 在 1.x 中保持兼容。

## 安装

```bash
pip install "verifiable-agent-auth-sdk==1.0.0rc1"

# 按需安装，不会把框架依赖塞进基础 SDK
pip install "verifiable-agent-auth-sdk[vault]==1.0.0rc1"
pip install "verifiable-agent-auth-sdk[redis]==1.0.0rc1"
pip install "verifiable-agent-auth-sdk[openai]==1.0.0rc1"
pip install "verifiable-agent-auth-sdk[openai-fastapi]==1.0.0rc1"
```

部署 Registry：

```bash
pip install "verifiable-agent-auth-registry==1.0.0rc1"
```

## 最短路径

```bash
agent-auth init
agent-auth doctor
```

本地配置无需 Vault 或 Registry，可直接运行示例：

```bash
python examples/local_signed_message.py
python examples/local_http_signing.py
```

生产配置完成后显式发布身份：

```bash
agent-auth provision
```

应用启动不会自动创建 Vault key，也不会自动发布身份。

## OpenAI Agents 接入

已有 `FunctionTool` 只需一行包装：

```python
from agent_auth_sdk.openai import OpenAIAgentAuth

auth = await OpenAIAgentAuth.from_env()
protected_tool = auth.protect_tool(existing_tool, target="security")
```

远程 Agent 作为真实身份边界：

```python
security_tool = auth.remote_tool(
    "security",
    input_type=SecurityRequest,
    output_type=SecurityResult,
)
```

`agent-auth.toml` 中声明一次目标身份和 URL：

```toml
[remotes.security]
agent_id = "agent://security.example.com/reviewer"
url = "https://security.example.com/invoke"
```

FastAPI 接收端不需要处理签名 header、nonce 或 Registry 查询：

```python
router = auth.router()

@router.endpoint("/invoke", request_model=SecurityRequest)
async def invoke(ctx, request):
    result = await Runner.run(security_agent, request.prompt)
    return SecurityResult(answer=result.final_output)

app.include_router(router)
```

同进程 `protect_tool()`、`agent_as_tool()` 和 handoff 只提供编排审计与应用级授权；需要真实身份边界时使用独立 HTTPS 服务和 `remote_tool()`。

## 安全边界

- Registry 管理员负责给 developer 分配 domain/path namespace；v1 不执行 DNS challenge。
- strict profile 要求 HTTPS、公共 DNS Agent identity 和固定 Vault key version。
- 私钥留在 Vault Transit，SDK 只读取公钥并请求签名。
- metadata capability 是经过认证的声明，不自动代表业务授权。
- 默认内存 nonce store 只适合单进程；多实例接收端使用 Redis extra。
- Registry 正式支持单节点、单 worker SQLite，不支持 HA。
- 配置 Registry 后默认 `registry_only`，Registry 不可用时失败关闭。

## 文档

- [Quick Start](https://github.com/YiheHuang/agent_auth_sdk/blob/main/QUICKSTART.md)
- [公开 API](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/API_REFERENCE.md)
- [OpenAI Agents 集成](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)
- [Examples](https://github.com/YiheHuang/agent_auth_sdk/tree/main/examples)
- [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)
- [安全模型](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)
- [协议 v1](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/PROTOCOL_V1.md)
- [从 0.2 beta 迁移](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/MIGRATION_0_2_TO_1_0.md)

安全问题请通过 [GitHub Security Advisory](https://github.com/YiheHuang/agent_auth_sdk/security/advisories/new) 私密报告。

License: MIT
