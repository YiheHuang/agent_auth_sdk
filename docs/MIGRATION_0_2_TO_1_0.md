# 从 0.2 beta 迁移到 1.0

1.0 保留 v1 wire protocol 和 Registry schema 1；主要变化是单身份配置、严格 Vault version、远程错误
envelope 和 OpenAI Agents 支持范围收口。

## 1. 更新依赖

```bash
pip install --pre --upgrade "verifiable-agent-auth-sdk[openai-fastapi,vault]==1.0.0rc1"
pip install --pre --upgrade "verifiable-agent-auth-registry==1.0.0rc1"
```

OpenAI Agents 正式范围由宽泛 beta 范围收窄为 `>=0.18.2,<0.19`。

## 2. 配置改为单身份

旧配置仍可读取：

```toml
roles = ["coordinator", "security"]
```

生产进程推荐改为：

```toml
identity = "agent://agents.example.com/coordinator"
endpoint = "https://agents.example.com/invoke"
public_base_url = "https://agents.example.com"

[vault]
key = "coordinator"
key_version = 1
```

`vault.verify` 和 `vault.token_file` 的相对路径都以 TOML 所在目录为基准。

## 3. 简化应用入口

```python
# 0.2 beta
auth = await OpenAIAgentAuth.from_env(identity="coordinator")

# 1.0
from agent_auth_sdk.openai import OpenAIAgentAuth
auth = await OpenAIAgentAuth.from_env()
```

远程 tool 可把 identity/URL 放入 `[remotes.<alias>]`，代码使用 `auth.remote_tool(alias, ...)`。
FastAPI 推荐 `router = auth.router()`、`@router.endpoint(...)`、`app.include_router(router)`。

## 4. Vault version

strict 应用启动要求 `vault.key_version`。若尚不知道版本，先运行 `agent-auth provision`，从输出 kid 的
`:vN` 读取版本，写回配置后运行 `agent-auth doctor`。

## 5. Registry

schema 仍为 1，无需数据迁移。升级前执行：

```bash
agent-auth-registry-admin db check
agent-auth-registry-admin db backup --output registry-before-1.0.sqlite3
```

旧 `/registry/agents/*` 在 1.x 保留但返回弃用 header；客户端应使用 `/v1/agents/*`。

## 6. 错误处理

远程服务错误现在使用 `{"error": {"code", "message", "request_id"}}`。应用优先捕获
`AgentAuthError` 并读取 `code`，不要解析错误文本。
