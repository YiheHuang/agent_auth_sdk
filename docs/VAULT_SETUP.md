# Vault 环境配置指南

`agent-auth-sdk` 使用 HashiCorp Vault Transit 管理私钥和签名。私钥始终存在于 Vault 中、不可导出；SDK 只读取公钥并通过 Transit API 执行签名。

---

## 1. 安装 Vault

从 [HashiCorp 官网](https://developer.hashicorp.com/vault/downloads) 下载 `vault` 二进制，放入 `PATH`。

```powershell
vault version
```

---

## 2. 配置持久化 Vault

以下为本地开发环境的完整配置流程，数据在重启后保留。

### 2.1 编写 config.hcl

```hcl
ui = true
disable_mlock = true

storage "file" {
  path = "runtime/vault/data"
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
```

### 2.2 启动、初始化、解封

```powershell
# 创建数据目录
mkdir runtime\vault\data

# 启动 Vault server（保持终端运行）
vault server -config=runtime\vault\config.hcl
```

另开终端：

```powershell
$env:VAULT_ADDR = "http://127.0.0.1:8200"

# 初始化（生成 root token 和解封密钥）
vault operator init -key-shares=1 -key-threshold=1 > runtime\vault\init.json

# 解封（从 init.json 中取出 unseal_keys_b64[0]）
vault operator unseal <unseal_key>

# 登录
vault login <root_token>
```

### 2.3 启用 Transit 引擎

```powershell
vault secrets enable transit
```

> 此时 Vault 已就绪。SDK 在调用 `from_vault(auto_create_key=True)` 时会自动创建 `ecdsa-p256` 类型的 Transit key，无需手动 `vault write`。

### 2.4 导出 token 供 SDK 使用

```powershell
mkdir runtime
Set-Content -Path runtime\vault-token.txt -Value "<root_token>"
```

SDK 通过 `vault_token_file` 读取此文件，无需通过环境变量传递 raw token。

### 2.5 生产环境注意

- 使用 HTTPS + TLS 证书，不设置 `tls_disable`
- 使用 `vault_token_file`，不传 raw `vault_token`
- Transit key 类型固定 `ecdsa-p256`，私钥不可导出
- 为每个 Agent 创建最小权限 policy（见第 3 节）
- 生产 token 建议由 Vault Agent、AppRole 或 OIDC 自动续租，避免长期静态 token

---

## 3. Vault Policy

为每个 Agent 分配最小权限。基础权限（仅签名）：

```hcl
path "transit/keys/weather-agent" {
  capabilities = ["read"]
}
path "transit/sign/weather-agent" {
  capabilities = ["update"]
}
```

若使用 `auto_create_key` 或 `rotate_key(new_key_name=...)` 让 SDK 自动管理 key，需额外授予创建权限：

```hcl
path "transit/keys/weather-agent*" {
  capabilities = ["read", "create", "update"]
}
path "transit/sign/weather-agent*" {
  capabilities = ["update"]
}
```

应用：

```powershell
vault policy write agent-weather agent-weather.hcl
```

---

## 4. SDK 配置

### VaultKmsConfig 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `vault_addr` | `str` | 是 | Vault 地址 |
| `transit_mount` | `str` | 是 | Transit mount path，通常 `"transit"` |
| `key_name` | `str` | 是 | Transit key 名称 |
| `vault_token_file` | `str \| Path` | 是 | Token 文件路径（SDK 读取首行） |
| `vault_token` | `str` | dev-only | Raw token，需配合 `allow_insecure_raw_token=True` |
| `namespace` | `str` | 否 | Vault Enterprise namespace |
| `verify` | `bool \| str` | 否 | TLS 校验（`False` 仅限 dev） |
| `kid` | `str` | 否 | 自定义 Key ID |
| `allow_insecure_raw_token` | `bool` | 否 | 显式允许 dev 模式使用 raw token |

### 创建 Agent

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.from_vault(
    domain="agent.example.com",
    name="weather",
    organization="Example Lab",
    endpoint="https://agent.example.com/tasks/handle",
    vault_addr="http://127.0.0.1:8200",
    vault_token_file="runtime/vault-token.txt",
    transit_mount="transit",
    key_name="weather-agent",
    auto_create_key=True,  # key 不存在时自动创建
)
```

---

## 5. 常见问题

### Key 类型错误

SDK 只支持 `ecdsa-p256`。若使用其他类型会报错：

```
ValueError: Unsupported Vault Transit key type. Expected ecdsa-p256.
```

```powershell
vault delete transit/keys/weather-agent
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

### Token 过期或权限不足

```
hvac.exceptions.Forbidden: permission denied
```

检查 token 状态：

```powershell
vault token lookup
```

### Token 文件不可读

```
ValueError: Unable to read Vault token file
```

确认文件路径正确且存在。若使用 Vault Agent sink file，确认 Vault Agent 已成功认证。

### 无法连接 Vault

- 确认 Vault server 正在运行：`vault status`
- 检查 `vault_addr` 是否可访问
- 检查防火墙规则
