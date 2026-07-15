# Quick Start

## 本地模式

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install "verifiable-agent-auth-sdk[openai]==1.0.0"
agent-auth init
agent-auth check
```

生成的 `agent-auth.toml` 使用 dev 模式和临时内存 key。将现有代码中的 `Runner.run` 换成：

```python
from agent_auth import AgentAuth

auth = AgentAuth()
auth.bind({"agent": coordinator})

async with auth:
    result = await auth.run(coordinator, user_input)
```

## 生产模式

### 1. Registry 管理员

```bash
agent-auth-registry-admin developer add \
  --client-id my-team \
  --domain agents.example.com \
  --path-prefix /team
```

命令只显示一次 API key。将其放入应用 secret：

```bash
export AGENT_AUTH_REGISTRY_API_KEY="aar_..."
```

### 2. Vault key 与权限

```bash
vault secrets enable transit                     # 已启用则跳过
vault write -f transit/keys/coordinator type=ecdsa-p256
```

应用 token 只需：

```hcl
path "transit/keys/coordinator" { capabilities = ["read"] }
path "transit/sign/coordinator" { capabilities = ["update"] }
```

执行 `agent-auth rotate` 的运维 token还需要 `transit/keys/coordinator/rotate` 的 `update` 权限。token 文件在 POSIX 系统必须为 `0600` 或更严格。

### 3. agent-auth.toml

```toml
version = 1
mode = "production"
registry = "https://registry.example.com"
state = ".agent-auth/state.sqlite3"
client_id = "my-team"

[vault]
url = "https://vault.example.com"
mount = "transit"
verify = "/etc/ssl/vault-ca.pem"

[agents.coordinator]
id = "agent://agents.example.com/team/coordinator"
endpoint = "https://agents.example.com/team/coordinator/invoke"
key = "coordinator"
key_version = 1
token_file = "/run/secrets/coordinator-vault-token"
capabilities = ["coordinate"]

[remotes]
researcher = "agent://agents.example.com/team/researcher"
```

生产要求 Agent ID host 与 endpoint host 完全相同。

### 4. 检查、发布与运行

```bash
agent-auth check
agent-auth publish coordinator
```

应用启动不会创建 Vault key、发布身份或读取 Registry developer API key。

### 5. 轮换与撤销

```bash
agent-auth rotate coordinator
agent-auth revoke coordinator
```

`rotate` 在 Registry 成功后原子更新 TOML 中的 `key_version`。若 Vault 已轮换但 Registry 请求失败，重试会复用未发布的新版本，不会连续创建版本。

常见稳定错误：`CONFIG_INVALID`、`VAULT_REQUEST_FAILED`、`REGISTRY_UNAVAILABLE`、`SIGNATURE_INVALID`、`AUDIENCE_MISMATCH`、`NONCE_REPLAYED`。
