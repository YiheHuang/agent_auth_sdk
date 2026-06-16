# Beta-v1 部署说明

目标：在 CentOS 服务器 `192.144.228.237` 上部署安全版中心 registry，并让开发者使用自己的 HashiCorp Vault Transit 完成 Agent 签名。

## 1. 架构边界

- `agent_auth_registry` 部署在你的服务器上，负责 developer 凭证、ownership 绑定、publish / rotate-key 验签与 `/.well-known/agent.json` 公开视图。
- `agent_auth_sdk` 运行在开发者或 agent 所在环境，负责读取 Vault Transit 公钥、调用 Vault Transit 签名、发布 metadata、发起 HTTP / message 签名。
- registry 不连接 Vault，不保存 Vault token，也不替开发者管理私钥。
- 开发者必须自行安装、初始化、解封、授权并配置 Vault。

## 2. 服务器准备

```bash
sudo yum update -y
sudo yum install -y python3 python3-pip nginx
sudo mkdir -p /opt/agent_auth_sdk
sudo chown -R $USER:$USER /opt/agent_auth_sdk
```

上传项目后安装：

```bash
cd /opt/agent_auth_sdk
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
pytest
```

## 3. Registry 环境变量

创建环境文件：

```bash
cp deploy/registry.env.example /opt/agent_auth_sdk/registry.env
```

推荐配置：

```bash
AGENT_REGISTRY_HOST=127.0.0.1
AGENT_REGISTRY_PORT=8008
AGENT_REGISTRY_DB_PATH=/opt/agent_auth_sdk/runtime/registry/registry.sqlite3
AGENT_REGISTRY_PATH=/opt/agent_auth_sdk/runtime/registry/.well-known/agent.json
AGENT_REGISTRY_ALLOWED_SKEW_SECONDS=300
```

## 4. systemd 与 Nginx

把 `deploy/registry.service` 拷到 `/etc/systemd/system/agent-auth-registry.service`，确认路径后启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable agent-auth-registry
sudo systemctl start agent-auth-registry
sudo systemctl status agent-auth-registry
```

把 `deploy/nginx.agent-auth.conf` 放到 `/etc/nginx/conf.d/agent-auth.conf`：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

目标效果：

- `http://192.144.228.237/.well-known/agent.json` 对外可读
- `http://192.144.228.237/registry/agents/publish` 可被 SDK 调用
- `http://192.144.228.237/registry/agents/rotate-key` 可被 SDK 调用

## 5. 初始化 Developer 凭证

```bash
source /opt/agent_auth_sdk/.venv/bin/activate
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin list-developers
```

查看 agent owner：

```bash
agent-auth-registry-admin inspect-agent --agent-id agent://demo.example.com/weather
```

## 6. 开发者侧 Vault 前置条件

开发者侧需要准备：

- Vault server
- 已启用的 Transit secrets engine
- `ecdsa-p256` Transit key
- 可读取 key metadata 与执行 sign 的 Vault token

本地演示：

```bash
vault server -dev -dev-root-token-id=root
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
vault secrets enable transit
vault write -f transit/keys/weather-agent type=ecdsa-p256
```

最小 policy 示例：

```hcl
path "transit/keys/*" {
  capabilities = ["read"]
}

path "transit/sign/*" {
  capabilities = ["update"]
}
```

## 7. 发布前自检

检查 Vault key：

```bash
agent-auth-sdk validate-kms-key \
  --vault-addr http://127.0.0.1:8200 \
  --vault-token-env VAULT_TOKEN \
  --transit-mount transit \
  --key-name weather-agent
```

渲染 metadata：

```bash
agent-auth-sdk render-metadata \
  --host demo.example.com \
  --agent-name weather \
  --endpoint https://demo.example.com/invoke \
  --vault-addr http://127.0.0.1:8200 \
  --vault-token-env VAULT_TOKEN \
  --transit-mount transit \
  --key-name weather-agent
```

发布到 registry：

```bash
export AGENT_AUTH_REGISTRY_API_KEY='your-registry-api-key'
agent-auth-sdk publish-to-registry \
  --metadata-path runtime/.well-known/agent.json \
  --vault-addr http://127.0.0.1:8200 \
  --vault-token-env VAULT_TOKEN \
  --transit-mount transit \
  --key-name weather-agent \
  --registry-url http://192.144.228.237/registry/agents/publish \
  --client-id developer-a
```

## 8. 密钥轮换

先由开发者在 Vault 中创建或准备新 key，然后走 registry 显式轮换：

```bash
agent-auth-sdk rotate-key \
  --registry-url http://192.144.228.237/registry/agents/rotate-key \
  --agent-id agent://demo.example.com/weather \
  --vault-addr http://127.0.0.1:8200 \
  --vault-token-env VAULT_TOKEN \
  --transit-mount transit \
  --current-kms-key-id weather-agent-current \
  --new-kms-key-id weather-agent-next \
  --client-id developer-a
```

## 9. 验收标准

- `curl http://192.144.228.237/.well-known/agent.json` 可返回文档
- 至少 1 个 Agent 成功通过 Vault Transit 签名发布 metadata
- registry 拒绝 owner 冲突、签名无效、过期 timestamp 和重放 nonce
- `agent-auth-registry-admin inspect-agent` 能看到 ownership 绑定

## 10. 备份建议

registry 需要备份：

- `/opt/agent_auth_sdk/runtime/registry/registry.sqlite3`
- `/opt/agent_auth_sdk/runtime/registry/.well-known/agent.json`

Vault 备份、解封密钥、高可用与审计由开发者自行负责。
