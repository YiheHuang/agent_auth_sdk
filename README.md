# Agent Auth SDK

`agent_auth_sdk` 是一个面向多 Agent 系统的 Python SDK，当前 beta-v1 的正式安全方案是：

- Agent 私钥不落本地文件系统
- 签名能力由开发者自己的 HashiCorp Vault Transit 提供
- metadata 发布到中心 registry 时，必须同时满足：
  - developer `client_id + api_key`
  - Agent 持钥证明
  - `agent_id` owner 绑定

这个项目只是 SDK 与 registry 协议实现。开发者必须自行安装、初始化、解封、授权并配置 Vault；SDK 不托管 Vault，也不代管任何私钥。

## 当前正式能力

- `agent://host/name` 格式的 `agent_id`
- 基于 Vault Transit `ecdsa-p256` 的云签名
- `ES256` 签名与验签
- `SignedAgentMessage` 规范消息
- `/.well-known/agent.json` metadata 导出与中心发现
- 安全发布：`POST /registry/agents/publish`
- 显式轮换：`POST /registry/agents/rotate-key`
- nonce 防重放
- metadata 缓存

## 安装

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
```

## 核心流程

1. registry 管理员先创建 developer 凭证。
2. 开发者自行部署 Vault，启用 Transit，并创建 `ecdsa-p256` key。
3. SDK 通过 Vault `read_key` 读取公钥，生成 metadata。
4. SDK 通过 Vault `sign_data` 对发布请求、HTTP 请求和消息签名。
5. registry 用 metadata 中声明的公钥验发布签名，并建立 owner 绑定。
6. 接收方通过 registry 解析 metadata，再用公钥验签。

registry 不需要 Vault token，也不需要访问 Vault。

## Vault 准备

本地演示可使用 dev-mode：

```bash
vault server -dev -dev-root-token-id=root
set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=root
vault secrets enable transit
vault write -f transit/keys/intake-agent type=ecdsa-p256
vault write -f transit/keys/triage-agent type=ecdsa-p256
vault write -f transit/keys/resolver-agent type=ecdsa-p256
vault write -f transit/keys/approval-agent type=ecdsa-p256
```

dev root token 只适合本地演示。准生产环境建议给 agent 单独 token，并至少限制为：

```hcl
path "transit/keys/*" {
  capabilities = ["read"]
}

path "transit/sign/*" {
  capabilities = ["update"]
}
```

## 最小使用方式

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.from_vault(
    domain="agent-a.example.com",
    name="weather",
    organization="A",
    endpoint="https://agent-a.example.com/invoke",
    vault_addr="http://127.0.0.1:8200",
    vault_token="root",
    transit_mount="transit",
    key_name="weather-agent",
    capabilities=["publish", "sign", "verify"],
)

agent.export_metadata("runtime")
```

发布到中心 registry：

```python
await agent.publish(
    registry_url="http://192.144.228.237/registry/agents/publish",
    client_id="developer-a",
    api_key="your-registry-api-key",
)
```

## 主要接口

- `AgentInstance.from_vault(...)`
- `AgentInstance.from_signer(...)`
- `VaultKmsConfig`
- `VaultTransitSigner`
- `VaultTransitPublicKeyResolver`
- `publish_to_registry(...)`
- `sign_http_request(...)`
- `verify_http_request(...)`
- `resolve_agent(...)`

`from_kms(...)` 只保留为兼容别名，正式文档入口是 `from_vault(...)`。

## CLI

创建本地开发 key：

```bash
agent-auth-sdk vault-create-key ^
  --vault-addr http://127.0.0.1:8200 ^
  --vault-token-env VAULT_TOKEN ^
  --transit-mount transit ^
  --key-name weather-agent
```

检查 Vault key：

```bash
agent-auth-sdk validate-kms-key ^
  --vault-addr http://127.0.0.1:8200 ^
  --vault-token-env VAULT_TOKEN ^
  --transit-mount transit ^
  --key-name weather-agent
```

渲染 metadata：

```bash
agent-auth-sdk render-metadata ^
  --host demo.example.com ^
  --agent-name weather ^
  --endpoint https://demo.example.com/invoke ^
  --vault-addr http://127.0.0.1:8200 ^
  --vault-token-env VAULT_TOKEN ^
  --transit-mount transit ^
  --key-name weather-agent
```

发布到中心 registry：

```bash
set VAULT_TOKEN=root
set AGENT_AUTH_REGISTRY_API_KEY=your-registry-api-key
agent-auth-sdk publish-to-registry ^
  --metadata-path runtime/.well-known/agent.json ^
  --vault-addr http://127.0.0.1:8200 ^
  --vault-token-env VAULT_TOKEN ^
  --transit-mount transit ^
  --key-name weather-agent ^
  --registry-url http://192.144.228.237/registry/agents/publish ^
  --client-id developer-a
```

显式轮换：

```bash
agent-auth-sdk rotate-key ^
  --registry-url http://192.144.228.237/registry/agents/rotate-key ^
  --agent-id agent://demo.example.com/weather ^
  --vault-addr http://127.0.0.1:8200 ^
  --vault-token-env VAULT_TOKEN ^
  --transit-mount transit ^
  --current-kms-key-id weather-agent-current ^
  --new-kms-key-id weather-agent-next ^
  --client-id developer-a
```

## Registry 管理

```bash
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin list-developers
agent-auth-registry-admin inspect-agent --agent-id agent://demo.example.com/weather
```

启动 registry 服务：

```bash
set AGENT_REGISTRY_DB_PATH=runtime/registry/registry.sqlite3
set AGENT_REGISTRY_PATH=runtime/registry/.well-known/agent.json
set AGENT_REGISTRY_PORT=8008
python -m agent_auth_registry.run
```

## 测试策略

- 协议级与 registry 安全测试默认可在本地运行
- 真实 Vault 集成测试要求：
  - `AGENT_AUTH_TEST_VAULT_ADDR`
  - `AGENT_AUTH_TEST_VAULT_TOKEN`
  - `AGENT_AUTH_TEST_VAULT_KEY_NAME`
  - 可选 `AGENT_AUTH_TEST_VAULT_TRANSIT_MOUNT`
- 未配置真实 Vault 时，Vault 集成测试会显式 `skip`

## 部署

CentOS 部署方案见 [deploy/DEPLOY_BETA_V1.md](/C:/Users/Yihe%20Huang/FDU/agent_auth_sdk/deploy/DEPLOY_BETA_V1.md)。
