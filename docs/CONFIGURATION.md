# 配置

`AgentAuth()` 默认读取当前目录 `agent-auth.toml`。可通过构造参数或 `AGENT_AUTH_CONFIG` 指定其他路径。配置中的 `${NAME}` 从环境变量展开；缺失时启动失败。

## 顶层字段

| 字段 | 必填 | 说明 |
|---|---|---|
| `version` | 是 | 固定为 `1` |
| `mode` | 是 | `dev`、`local` 或 `production` |
| `registry` | local/production | Registry base URL |
| `state` | 否 | nonce SQLite；默认 `.agent-auth/state.sqlite3` |
| `client_id` | publish/rotate/revoke | Registry developer client ID |

`AGENT_AUTH_REGISTRY_API_KEY` 只从环境变量读取，不得写入 TOML。

## Vault

```toml
[vault]
url = "https://vault.example.com"
mount = "transit"
verify = "/etc/ssl/vault-ca.pem"
namespace = "team" # 可选
```

`verify` 为 `true`、`false` 或 CA 文件路径；production 不应设为 `false`。token 优先读取 `AGENT_AUTH_VAULT_TOKEN_<ALIAS>`，其次读取 `AGENT_AUTH_VAULT_TOKEN`，最后读取 identity 的 `token_file`。POSIX token 文件权限必须为 `0600` 或更严格。

| 字段 | 必填 | 说明 |
|---|---|---|
| `url` | local/production | Vault base URL |
| `mount` | 否 | Transit mount，默认 `transit` |
| `verify` | 否 | TLS 校验开关或 CA 文件，默认 `true` |
| `namespace` | 否 | Vault Enterprise namespace |

## 身份与远程别名

```toml
[agents.coordinator]
id = "agent://agents.example.com/team/coordinator"
endpoint = "https://agents.example.com/coordinator/invoke"
key = "coordinator"
key_version = 2
token_file = "/run/secrets/coordinator-vault-token"
capabilities = ["coordinate"]

[remotes]
researcher = "agent://agents.example.com/team/researcher"
```

| identity 字段 | 必填 | 说明 |
|---|---|---|
| `id` | 是 | 规范化 Agent ID |
| `endpoint` | 是 | 接收 SignedEnvelope 的 URL |
| `key` | local/production | Vault Transit key 名称 |
| `key_version` | local/production | 固定正整数版本 |
| `token_file` | 否 | Vault token 文件；也可用环境变量 |
| `capabilities` | 否 | 已认证声明的字符串列表，默认空 |

`[remotes]` 将远程 alias 映射到 Agent ID；endpoint 始终从 Registry 解析，不在此重复配置。

- alias 只在本进程内使用；Agent ID 是协议身份。
- production 的 Agent ID 必须是规范化公网 DNS URI，endpoint 必须使用相同 host 的 HTTPS。
- local 的 Agent ID 必须使用 `agent://localhost/...`，所有 endpoint、Registry 和 Vault 只能使用 loopback。
- key version 必须固定；Vault 内部轮换后需执行 `agent-auth rotate <alias>`。

## 模式差异

| 行为 | dev | local | production |
|---|---|---|---|
| signer | 进程内临时 P-256 | Vault Transit | Vault Transit |
| nonce | 内存 | SQLite | SQLite |
| Registry | 进程内记录或可选服务 | 必需、loopback | 必需、公网 HTTPS |
| identity | 宽松开发地址 | 仅 localhost | 规范化公网 DNS |
| 重启后密钥稳定 | 否 | 是 | 是 |

dev 仅适合测试；local 适合本机真实集成；production 才是公开网络部署模式。

## CLI

```text
agent-auth [--config PATH] init [--force]
agent-auth [--config PATH] check
agent-auth [--config PATH] publish [alias]
agent-auth [--config PATH] rotate <alias>
agent-auth [--config PATH] revoke <alias>
```

- `init` 只生成 dev 模板，不创建 key 或发布身份。
- `check` 只读检查配置；local/production 同时检查 Vault key version、Registry readiness 和发布状态。
- `publish` 首次注册或更新 endpoint/capabilities；需要 `client_id` 和 `AGENT_AUTH_REGISTRY_API_KEY`。
- `rotate` 轮换 Vault key、提交双 key proof，并在成功后原子更新 TOML 中的 `key_version`。
- `revoke` 撤销 Agent；撤销后的 Agent ID 和 kid 不可复用。
