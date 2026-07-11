# Quick Start：Vault + HTTPS Registry

本指南完成一条生产形态的最小闭环：为 sender 和 receiver 创建 Vault Transit key，向中心 Registry 发布两个身份，然后签名并验证一条绑定 receiver 的消息。

预计用时 15–30 分钟。命令使用 Linux/macOS shell；Windows 用户可在 WSL 中执行基础设施命令，Python 示例本身跨平台。

## 1. 前置条件

- Python 3.11–3.13。
- 一个可访问的 HTTPS Registry，例如 `https://registry.example.com`。
- 一个可访问的 HTTPS Vault，已启用 Transit secrets engine。
- 一个由 Registry 管理员确认归属的 Agent identity domain，例如 `agents.example.com`。

如果尚未部署 Registry，先完成 [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)。

安装 SDK：

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "verifiable-agent-auth-sdk[vault]==0.2.0b1"
```

## 2. 创建 developer 和 namespace

在 Registry 主机上，以 Registry 服务使用的环境变量运行：admin 命令直接访问同一个 SQLite 数据库。

```bash
agent-auth-registry-admin create-developer --client-id quickstart-dev
```

命令只显示一次 API key。将 `api_key` 保存到 secret manager，然后分配 namespace：

```bash
agent-auth-registry-admin grant-namespace \
  --client-id quickstart-dev \
  --domain agents.example.com \
  --path-prefix /quickstart
```

此授权只允许 `quickstart-dev` 管理：

```text
agent://agents.example.com/quickstart/...
```

## 3. 创建 Vault Transit keys

以下命令由 Vault 管理员执行。如果 `transit/` 已启用，不要重复执行第一条命令。

```bash
vault secrets enable transit
vault write -f transit/keys/quickstart-sender type=ecdsa-p256
vault write -f transit/keys/quickstart-receiver type=ecdsa-p256
```

为运行示例的身份创建最小策略。它只允许读取两把公钥并请求签名，不允许删除或修改 key 配置：

```hcl
# quickstart-agent-auth.hcl
path "transit/keys/quickstart-sender" {
  capabilities = ["read"]
}
path "transit/sign/quickstart-sender" {
  capabilities = ["update"]
}
path "transit/keys/quickstart-receiver" {
  capabilities = ["read"]
}
path "transit/sign/quickstart-receiver" {
  capabilities = ["update"]
}
```

```bash
vault policy write quickstart-agent-auth quickstart-agent-auth.hcl
install -d -m 700 "$HOME/.agent-auth"
umask 077
vault token create -policy=quickstart-agent-auth -field=token > "$HOME/.agent-auth/vault-token"
chmod 600 "$HOME/.agent-auth/vault-token"
```

生产环境推荐 Vault Agent 或 AppRole 写入短期 token 文件，不要长期保存手工创建的 token。

## 4. 配置环境变量

```bash
export AGENT_AUTH_REGISTRY_URL="https://registry.example.com"
export AGENT_AUTH_REGISTRY_CLIENT_ID="quickstart-dev"
export AGENT_AUTH_REGISTRY_API_KEY="粘贴第 2 步只显示一次的 API key"

export AGENT_AUTH_AGENT_DOMAIN="agents.example.com"
export AGENT_AUTH_VAULT_ADDR="https://vault.example.com"
export AGENT_AUTH_VAULT_TOKEN_FILE="$HOME/.agent-auth/vault-token"
export AGENT_AUTH_VAULT_TRANSIT_MOUNT="transit"
# Vault Enterprise namespace 可选：
# export AGENT_AUTH_VAULT_NAMESPACE="your-namespace"
export AGENT_AUTH_SENDER_KEY_NAME="quickstart-sender"
export AGENT_AUTH_RECEIVER_KEY_NAME="quickstart-receiver"

# 使用私有 CA 时设置 CA bundle；未设置时使用系统 CA。
# export AGENT_AUTH_VAULT_VERIFY="/etc/ssl/certs/your-vault-ca.pem"
```

不要把这些值提交到 Git。示例只读取环境变量，不输出 API key 或 Vault token。

## 5. 发布并验签

从源码仓库运行权威 Quick Start 示例：

```bash
git clone https://github.com/YiheHuang/agent_auth_sdk.git
cd agent_auth_sdk
python examples/vault_registry_quickstart.py
```

预期输出：

```text
published sender: agent://agents.example.com/quickstart/sender
published receiver: agent://agents.example.com/quickstart/receiver
verified sender: agent://agents.example.com/quickstart/sender
verified recipient: agent://agents.example.com/quickstart/receiver
payload: {'task': 'quickstart', 'status': 'ready'}
```

重复运行会由同一 developer 和当前 key 更新相同身份，不会创建新的 agent_id。

## 6. 检查 Registry

```bash
curl --fail --silent --show-error \
  --get "https://registry.example.com/v1/agents/resolve" \
  --data-urlencode "agent_id=agent://agents.example.com/quickstart/sender"
```

返回内容应包含 sender metadata 和 Vault key version 对应的 `kid`。

## 常见错误

| 错误 | 检查项 |
|---|---|
| `403 namespace not authorized` | namespace domain 是否与 `AGENT_AUTH_AGENT_DOMAIN` 完全一致，前缀是否为 `/quickstart` |
| `Vault token file permissions are too broad` | POSIX 权限必须为 `0600` 或更严格 |
| `permission denied` from Vault | token 是否拥有对应 `transit/keys/*` 的 `read` 和 `transit/sign/*` 的 `update` |
| `METADATA_FETCH_FAILED` | Registry URL、TLS/CA、Agent 是否已发布；strict profile 不允许 HTTP |
| `TIMESTAMP_EXPIRED` | Registry、Vault 客户端和 Agent 主机是否使用 NTP 同步 |
| `RECIPIENT_MISMATCH` | 验签时的 `expected_recipient` 必须与消息中的 recipient 完全一致 |
| `NONCE_REPLAYED` | 同一签名消息不能重复提交；重新签名会生成新 nonce |

下一步可以运行 [远程 HTTP 示例](https://github.com/YiheHuang/agent_auth_sdk/tree/main/examples/remote_agent)，或阅读 [OpenAI Agents 集成](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/OPENAI_AGENTS.md)。
