# Vault 环境配置指南

`agent-auth-sdk` 使用 HashiCorp Vault Transit 作为私钥管理和签名后端。SDK **不生成、不保存、不加载本地私钥**——私钥始终存在于 Vault 中，不可导出；SDK 只读取 Transit 公钥并通过 Transit API 执行签名。

---

## 1. 为什么需要 Vault

Agent Auth SDK 的安全模型中，Agent 的私钥是身份的根基。一旦私钥泄露，攻击者可以伪造该 Agent 的所有签名。Vault Transit 引擎提供：

- **私钥不出 Vault**：`ecdsa-p256` key 的 `exportable=false`，私钥永远不会离开 Vault
- **签名审计**：每次签名调用都被 Vault 审计日志记录
- **Token 生命周期管理**：通过 Vault Agent / AppRole / OIDC 自动续租短期 token
- **策略隔离**：每个 Agent 只能使用自己的 Transit key

SDK 与 Vault 的关系：

```
┌─────────────────────┐      ┌──────────────────────┐
│   agent-auth-sdk     │      │  HashiCorp Vault      │
│                      │ read │                      │
│  AgentInstance  ─────┼─────►│  transit/keys/{name}  │  公钥
│                      │ sign │                      │
│  sign_http()    ─────┼─────►│  transit/sign/{name}  │  签名
│  sign_message()      │      │                      │
└─────────────────────┘      └──────────────────────┘
```

---

## 2. Vault 安装与启动

### 2.1 安装 Vault

从 [HashiCorp 官网](https://developer.hashicorp.com/vault/downloads) 下载对应平台的 `vault` 二进制，放入 `PATH`。

验证安装：

```powershell
vault version
```

### 2.2 本地开发 — Dev Server

Vault dev server 内嵌于内存，启动即已初始化、解封，root token 为指定值。**仅适合本地开发，重启后所有数据丢失。**

```powershell
vault server -dev -dev-root-token-id=root
```

另开终端，设置环境变量并启用 Transit：

```powershell
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "root"

vault secrets enable transit
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

将 root token 写入文件供 SDK 读取：

```powershell
New-Item -ItemType Directory -Force runtime | Out-Null
Set-Content -Path runtime/vault-token.txt -Value "root"
```

### 2.3 本地开发 — 持久化 Vault

如果希望本地数据在重启后保留（比如 demo 项目），可以使用 file storage + 手动初始化的方式。Demo 项目提供了一键脚本：

```powershell
cd agent_auth_demoproject
.\setup-persistent-vault.ps1
```

该脚本自动完成：创建 file storage 配置 → 启动 Vault → 首次初始化 → 解封 → 启用 Transit → 创建 demo Agent 对应的 4 个 `ecdsa-p256` key → 生成环境变量脚本。

等价的手动步骤：

```powershell
# 1. 创建配置目录
mkdir runtime\vault\data

# 2. 编写 config.hcl
@"
ui = true
disable_mlock = true

storage "file" {
  path = "runtime/vault/data"
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
"@ | Set-Content runtime\vault\config.hcl

# 3. 启动 Vault server
vault server -config=runtime\vault\config.hcl

# 4. 另开终端，初始化
$env:VAULT_ADDR = "http://127.0.0.1:8200"
vault operator init -key-shares=1 -key-threshold=1 > runtime\vault\init.json

# 5. 解封
vault operator unseal <unseal_key_从_init.json_中获取>

# 6. 登录
vault login <root_token_从_init.json_中获取>

# 7. 启用 Transit 并创建 key
vault secrets enable transit
vault write -f transit/keys/weather-agent type=ecdsa-p256

# 8. 导出 token 供 SDK 使用
Set-Content -Path runtime\vault-token.txt -Value "<root_token>"
```

---

## 3. 生产环境配置

### 3.1 架构原则

生产环境必须满足：

| 要求 | 说明 |
|------|------|
| 使用 `vault_token_file` | 不通过环境变量或代码传递 raw token |
| Vault TLS 不关闭 | `verify=True`（默认），SDK 会拒绝 `verify=False`（除非显式开启 dev 模式） |
| Transit key 不可导出 | `type=ecdsa-p256`，SDK 仅支持此类型 |
| 最小权限 Vault policy | 每个 Agent 只授予自己 key 的 `read` + `sign` 权限 |
| Token 短期自动续租 | 使用 Vault Agent sink file 或平台身份系统 |

### 3.2 Vault 服务端配置

生产 `config.hcl` 示例：

```hcl
ui = true
disable_mlock = true

storage "raft" {
  path = "/opt/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"
}

api_addr = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"
```

### 3.3 创建 Transit Key

```powershell
$env:VAULT_ADDR = "https://vault.example.com:8200"
$env:VAULT_TOKEN = "<admin_token>"

vault secrets enable transit
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

### 3.4 Vault Policy（最小权限）

为每个 Agent 创建最小权限 policy：

```hcl
# policy: agent-weather（基础权限：仅读取公钥 + 签名）
path "transit/keys/weather-agent" {
  capabilities = ["read"]
}

path "transit/sign/weather-agent" {
  capabilities = ["update"]
}
```

若使用 `from_vault(auto_create_key=True)` 或 `rotate_key(new_key_name=...)` 让 SDK 自动管理 Vault key，还需授予 key 创建权限。可使用通配符覆盖多个 key：

```hcl
# policy: agent-weather（含 key 自动创建权限）
path "transit/keys/weather-agent*" {
  capabilities = ["read", "create", "update"]
}

path "transit/sign/weather-agent*" {
  capabilities = ["update"]
}
```

> 通配符 `*` 使得 `weather-agent`、`weather-agent-v2`、`weather-agent-v3` 等 key 均可匹配。`create` + `update` 权限允许 SDK 调用 `create_key()` 和 `update_key_configuration()`。

应用 policy：

```powershell
vault policy write agent-weather agent-weather.hcl
```

### 3.5 Token 管理

#### 方案 A：Vault Agent（推荐）

Vault Agent 通过 AppRole、OIDC 或云平台身份自动认证，将短期 token 写入 sink file，SDK 只需读取该文件。

Vault Agent 配置示例（`agent-config.hcl`）：

```hcl
pid_file = "/opt/vault/agent/pid"

auto_auth {
  method {
    type = "approle"
    config = {
      role_id_file_path   = "/opt/vault/agent/role-id"
      secret_id_file_path = "/opt/vault/agent/secret-id"
    }
  }

  sink {
    type = "file"
    config = {
      path = "/run/secrets/vault-token"
    }
  }
}
```

此时 SDK 配置：

```python
agent = AgentInstance.from_vault(
    domain="agent.example.com",
    name="weather",
    organization="Example Lab",
    endpoint="https://agent.example.com/tasks/handle",
    vault_addr="https://vault.example.com:8200",
    vault_token_file="/run/secrets/vault-token",
    transit_mount="transit",
    key_name="weather-agent",
)
```

#### 方案 B：手动创建 Token

创建一个绑定 policy 的短期 token（需配合外部定时刷新）：

```powershell
vault token create -policy=agent-weather -ttl=24h -format=json
```

#### 方案 C：Kubernetes Auth（K8s 环境）

```powershell
# 启用 K8s auth
vault auth enable kubernetes

# 配置
vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443"

# 创建角色
vault write auth/kubernetes/role/agent-weather \
    bound_service_account_names=agent-weather \
    bound_service_account_namespaces=default \
    policies=agent-weather \
    ttl=24h
```

---

## 4. SDK 中的 Vault 配置

### 4.1 VaultKmsConfig 参数表

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `vault_addr` | `str` | 是 | — | Vault 服务地址（含 `http://` 或 `https://`） |
| `transit_mount` | `str` | 是 | — | Transit 引擎 mount path，常见 `"transit"` |
| `key_name` | `str` | 是 | — | Transit 中的 key name |
| `vault_token_file` | `str \| Path` | 生产必填 | `None` | Token 文件路径（SDK 读取第一行） |
| `vault_token` | `str` | dev-only | `None` | Raw token，需配合 `allow_insecure_raw_token=True` |
| `namespace` | `str` | 否 | `None` | Vault Enterprise namespace |
| `verify` | `bool \| str` | 否 | `True` | TLS 校验证书（`False` 仅限 dev，`str` 为 CA 文件路径） |
| `kid` | `str` | 否 | `"vault:{mount}/{key}"` | 自定义 Key ID |
| `allow_insecure_raw_token` | `bool` | 否 | `False` | 显式允许 dev/test 使用 raw token |

### 4.2 安全约束

SDK 内置以下硬约束，拒绝不安全的配置：

```python
# ❌ 生产中使用 raw token — 抛出 ValueError
VaultKmsConfig(
    vault_addr="https://vault.example.com",
    transit_mount="transit",
    key_name="weather-agent",
    vault_token="raw-token",
)
# ValueError: Raw vault_token is dev/test-only. Use vault_token_file in production.

# ❌ 关闭 TLS 但未显式声明 dev 模式 — 抛出 ValueError
VaultKmsConfig(
    vault_addr="https://vault.example.com",
    transit_mount="transit",
    key_name="weather-agent",
    vault_token_file="runtime/token.txt",
    verify=False,
)
# ValueError: Disabling Vault TLS verification is only allowed in explicit dev/test mode.

# ✅ 本地开发正确用法
VaultKmsConfig(
    vault_addr="http://127.0.0.1:8200",
    transit_mount="transit",
    key_name="weather-agent",
    vault_token="root",
    allow_insecure_raw_token=True,
    verify=True,
)
```

### 4.3 AgentInstance.from_vault() 的参数映射

`from_vault()` 内部调用链：

```
from_vault(direct_params)
  → VaultKmsConfig(direct_params)     # 构造 Vault 配置
  → VaultTransitSigner(config)        # 创建签名器（使用 hvac）
  → signer.validate_access()          # 用空消息探测签名权限
  → resolve_vault_public_key(config)  # 读取 Transit 公钥
  → from_signer(signer, public_key)   # 完成 AgentInstance 构造
```

如果 `validate_access()` 或 `resolve_vault_public_key()` 失败（如 token 过期、权限不足、key 不存在），会抛出 `ValueError` 或 `hvac` 相关异常。

---

## 5. 验证 Vault 配置

### 5.1 命令行验证

```powershell
# 读取公钥
vault read transit/keys/weather-agent

# 测试签名
vault write transit/sign/weather-agent \
    hash_input=$(echo -n "test" | base64) \
    hash_algorithm=sha2-256 \
    marshaling_algorithm=asn1
```

### 5.2 SDK 验证工具

```python
import os
from agent_auth_sdk.vault_kms import VaultKmsConfig, validate_vault_key

info = validate_vault_key(
    VaultKmsConfig(
        vault_addr=os.environ["VAULT_ADDR"],
        vault_token_file="runtime/vault-token.txt",
        transit_mount="transit",
        key_name="weather-agent",
    )
)
print(f"Key: {info.key_name}, Type: {info.key_type}, Version: {info.latest_version}")
print(f"Public Key (PEM):\n{info.public_key_pem}")
```

---

## 6. 常见问题

### Key 类型错误

SDK 只支持 `ecdsa-p256`。如果创建了其他类型：

```
ValueError: Unsupported Vault Transit key type: rsa-2048. Expected ecdsa-p256.
```

**解决**：删除旧 key 后重新创建：

```powershell
vault delete transit/keys/weather-agent
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

### Token 过期

```
hvac.exceptions.Forbidden: permission denied
```

或 SDK 在调用 `validate_access()` 或 `sign()` 时抛出异常。

**解决**：检查 token 是否过期或权限不足：

```powershell
vault token lookup
```

### Token 文件不可读

```
ValueError: Unable to read Vault token file: runtime/vault-token.txt
```

**解决**：确认文件存在且可读。如果使用了 Vault Agent sink file，确认 Vault Agent 正常运行且已成功认证。

### 无法连接 Vault

```
hvac.exceptions.VaultError: ConnectionError
```

**解决**：
- 确认 Vault server 正在运行：`vault status`
- 确认 `vault_addr` 可访问（注意 Docker 内网与宿主机网络差异）
- 检查防火墙规则

---

## 7. 参考链接

- [HashiCorp Vault 官方文档](https://developer.hashicorp.com/vault/docs)
- [Vault Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Vault Agent Auto-Auth](https://developer.hashicorp.com/vault/docs/agent/autoauth)
- [hvac (Vault Python Client)](https://hvac.readthedocs.io/)
