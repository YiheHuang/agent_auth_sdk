# 可运行示例

所有命令从仓库根目录执行。基础安装：

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[all]"
python -m pip install -e packages/agent-auth-registry
```

| 示例 | 外部依赖 | 安全级别 | 命令 |
|---|---|---|---|
| `local_signed_message` | 无 | 仅本地演示 | `python -m examples.local_signed_message` |
| `local_http_signing` | 无 | 仅本地演示 | `python -m examples.local_http_signing` |
| `vault_registry_quickstart` | Vault + HTTPS Registry | 生产形态 | `python -m examples.vault_registry_quickstart` |
| `key_lifecycle` | Vault + HTTPS Registry | 生产运维 | `python -m examples.key_lifecycle --help` |
| `remote_agent` | Vault + Registry + FastAPI | 生产形态 | 见下文 |
| `openai_agents.offline_local` | `openai` extra | `bind` + 原生 Agent-as-tool 离线契约 | `python -m examples.openai_agents.offline_local` |
| `openai_agents.live_local` | OpenAI API Key | 同进程 | `python -m examples.openai_agents.live_local` |
| `openai_agents.remote_*` | OpenAI + Vault + Registry | 远程边界 | 见下文 |

`examples._shared.LocalEs256Signer` 每次启动都会生成新私钥，只用于本地示例和 CI。生产示例只使用 Vault Transit。

## Vault/Registry 公共环境变量

```bash
export AGENT_AUTH_REGISTRY_URL="https://registry.example.com"
export AGENT_AUTH_REGISTRY_CLIENT_ID="developer-a"
export AGENT_AUTH_REGISTRY_API_KEY="从 secret manager 注入"
export AGENT_AUTH_AGENT_DOMAIN="agents.example.com"

export AGENT_AUTH_VAULT_ADDR="https://vault.example.com"
export AGENT_AUTH_VAULT_TOKEN_FILE="/run/secrets/vault-token"
export AGENT_AUTH_VAULT_TRANSIT_MOUNT="transit"
# Vault Enterprise namespace 可选
# export AGENT_AUTH_VAULT_NAMESPACE="your-namespace"
# true、false 或 CA bundle 路径
export AGENT_AUTH_VAULT_VERIFY="true"
```

完整初始化见 [`QUICKSTART.md`](../QUICKSTART.md)。任何示例都不会输出 API key、Vault token 或私钥。

## 本地消息

```bash
python -m examples.local_signed_message
```

预期输出包含一次成功、一次 `NONCE_REPLAYED` 和一次 `SIGNATURE_INVALID`。

## 本地 HTTP

```bash
python -m examples.local_http_signing
```

示例对实际 canonical JSON bytes 签名，并证明 body 修改后验签失败。

## Vault + Registry Quick Start

需要：

```bash
export AGENT_AUTH_SENDER_KEY_NAME="quickstart-sender"
export AGENT_AUTH_RECEIVER_KEY_NAME="quickstart-receiver"
python -m examples.vault_registry_quickstart
```

对应 Agent names 为 `quickstart/sender` 和 `quickstart/receiver`，developer namespace 必须覆盖 `/quickstart`。

## 密钥生命周期

先设置当前 Agent 和 Vault key：

```bash
export AGENT_AUTH_AGENT_NAME="quickstart/sender"
export AGENT_AUTH_CURRENT_KEY_NAME="quickstart-sender"
```

新 key 应由 Vault 管理员预创建并授权 runtime token 读取/签名：

```bash
python -m examples.key_lifecycle add --new-key-name quickstart-sender-secondary
python -m examples.key_lifecycle rotate --new-key-name quickstart-sender-v2
python -m examples.key_lifecycle revoke --kid 'vault:transit/quickstart-sender:v1' --yes
```

`revoke` 不可逆且拒绝撤销当前 signing kid。命令不会删除 Vault key。

## 远程 HTTP Agent

receiver identity 必须已发布，且 metadata endpoint 与实际 URL 一致：

```bash
export AGENT_AUTH_SENDER_KEY_NAME="quickstart-sender"
export AGENT_AUTH_RECEIVER_KEY_NAME="quickstart-receiver"
export AGENT_AUTH_RECEIVER_URL="https://receiver.example.com/invoke"
```

终端 1：

```bash
uvicorn examples.remote_agent.receiver:app --host 127.0.0.1 --port 8010
```

在 Nginx/TLS 后暴露为 `AGENT_AUTH_RECEIVER_URL`。终端 2：

```bash
python -m examples.remote_agent.sender
```

receiver middleware 验证请求并写入 `request.state.agent_auth`；业务 handler 使用认证 sender 作为签名响应 recipient；sender 再验证 target identity 和响应 recipient。

## OpenAI Agents：离线契约

```bash
python -m examples.openai_agents.offline_local
```

它使用真实 `Agent.as_tool()` 和 `OpenAIAgentAuth.agent_as_tool()`，但 Model 返回确定性本地结果，
不访问 OpenAI API。示例同时打印不含 payload/凭证的结构化认证事件。

## OpenAI Agents：真实同进程调用

```bash
export OPENAI_API_KEY="从 secret manager 注入"
# 可选；未设置时使用 OpenAI Agents SDK 默认模型
export OPENAI_DEFAULT_MODEL="你已验证可用的模型"
python -m examples.openai_agents.live_local
```

同进程 wrapper 验证编排边界，不隔离同一 Python 进程中的代码。

## OpenAI Agents：远程边界

先为 namespace 创建并授权 `specialist`、`caller` 两把 Vault key：

```bash
export OPENAI_API_KEY="从 secret manager 注入"
export AGENT_AUTH_SPECIALIST_KEY_NAME="openai-specialist"
export AGENT_AUTH_CALLER_KEY_NAME="openai-caller"
export AGENT_AUTH_OPENAI_REMOTE_URL="https://specialist.example.com/invoke"
```

终端 1：

```bash
uvicorn examples.openai_agents.remote_server:app --host 127.0.0.1 --port 8020
```

终端 2：

```bash
python -m examples.openai_agents.remote_client
```

server 和 client 启动时都会发布自己的 Vault identity。Registry namespace 必须覆盖 `/specialist` 和 `/caller`；生产 Nginx 将 8020 的 `/invoke` 暴露为 HTTPS URL。
