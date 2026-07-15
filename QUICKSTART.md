# Quick Start

## 五分钟本地体验

本地模式生成临时 ES256 key，只用于理解流程，不代表生产安全边界。

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install "verifiable-agent-auth-sdk[openai-fastapi]==1.0.0rc1"
agent-auth init
agent-auth doctor
```

上面三条命令只依赖 PyPI 安装包。若要运行仓库附带的两个无基础设施示例，请另外取得源码：

```bash
git clone https://github.com/YiheHuang/agent_auth_sdk.git
cd agent_auth_sdk
python examples/local_signed_message.py
python examples/local_http_signing.py
```

预期看到正常验签成功，并且篡改或重复提交失败。

## 生产配置：Vault + HTTPS Registry

前置条件：HTTPS Registry、HTTPS Vault Transit、由 Registry 管理员确认归属的 DNS domain。strict profile 不接受 IP、localhost 或明文 HTTP。

### 1. Registry 管理员创建 developer

```bash
agent-auth-registry-admin create-developer --client-id my-team
agent-auth-registry-admin grant-namespace \
  --client-id my-team \
  --domain agents.example.com \
  --path-prefix /coordinator
```

API key 只显示一次，应放入 secret manager。

### 2. Vault 管理员创建 key

```bash
vault secrets enable transit  # 已启用时跳过
vault write -f transit/keys/coordinator type=ecdsa-p256
```

应用 token 只需要：

```hcl
path "transit/keys/coordinator" { capabilities = ["read"] }
path "transit/sign/coordinator" { capabilities = ["update"] }
```

token 文件在 Linux/macOS 上必须为 `0600` 或更严格。

### 3. 生成并编辑配置

```bash
agent-auth init \
  --mode vault \
  --roles coordinator \
  --domain agents.example.com \
  --organization "Example Team"
```

编辑 `.agent-auth/agent-auth.toml`：

```toml
mode = "vault"
identity = "agent://agents.example.com/coordinator"
endpoint = "https://agents.example.com/invoke"
public_base_url = "https://agents.example.com"
profile = "strict"

[registry]
url = "https://registry.example.com"
publish_url = "https://registry.example.com/v1/agents/publish"
client_id = "${AGENT_AUTH_REGISTRY_CLIENT_ID}"
api_key = "${AGENT_AUTH_REGISTRY_API_KEY}"

[vault]
addr = "https://vault.example.com"
token_file = "../secrets/vault-token"
verify = "../certs/vault-ca.pem" # 使用公共 CA 时写 true
key = "coordinator"
auto_create_keys = false
```

设置凭证环境变量：

```bash
export AGENT_AUTH_REGISTRY_CLIENT_ID="my-team"
export AGENT_AUTH_REGISTRY_API_KEY="replace-me"
```

Windows PowerShell 使用 `$env:NAME="value"`。

### 4. 检查并发布

```bash
agent-auth doctor
agent-auth provision
```

首次 provision 输出的 `kid` 末尾包含 Vault 版本，例如 `:v1`。将版本固定到配置：

```toml
[vault]
key_version = 1
```

之后再次运行：

```bash
agent-auth doctor
```

应用运行阶段只加载这一个固定身份，不会创建 key 或重复发布。

### 5. 在代码中加载

```python
from agent_auth_sdk.openai import OpenAIAgentAuth

auth = await OpenAIAgentAuth.from_env()
async with auth:
    print(auth.agent.agent_id, auth.agent.kid)
```

完整的两个 Agent 签名、发布和 recipient-bound 验签示例见 [`examples/vault_registry_quickstart.py`](https://github.com/YiheHuang/agent_auth_sdk/blob/main/examples/vault_registry_quickstart.py)。

## 常见错误

| code/错误 | 处理 |
|---|---|
| `VAULT_KEY_VERSION_REQUIRED` | provision 后把 `kid` 中的版本写入 `vault.key_version` |
| `VAULT_CA_INVALID` | 检查 `vault.verify`；相对路径以 TOML 所在目录为基准 |
| `VAULT_TOKEN_PERMISSION_DENIED` | 将 token 文件权限收紧为 `0600` |
| `METADATA_FETCH_FAILED` | 检查 Registry URL、TLS 和身份是否已发布 |
| `RECIPIENT_MISMATCH` | 请求中的 recipient 必须等于接收方完整 agent_id |
| `NONCE_REPLAYED` | 同一签名只能消费一次，重新签名会生成新 nonce |
| Registry 403 | 检查 developer 状态和 domain/path namespace |

生产部署继续阅读 [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)。
