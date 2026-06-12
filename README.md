# Agent Auth SDK

一个最小可发布的 Python SDK，用于完成三件事：

- 创建 Agent 身份、公私钥与 metadata
- 发送带签名的 Agent 消息或 HTTP 请求
- 从中心注册表 `/.well-known/agent.json` 解析并验证 Agent 身份

仓库当前只保留四类内容：

- SDK 主包：`agent_auth_sdk/`
- 中心 registry 服务：`agent_auth_registry/`
- 测试套件：`pytests/`
- 部署资产：`deploy/`

## 能力

- `agent://host/name` 格式的 `agent_id`
- Ed25519 密钥生成、签名、验签
- `SignedAgentMessage` 规范消息
- `/.well-known/agent.json` metadata 发布
- 中心注册表发布：`POST /registry/agents`
- 中心注册表发现：`GET /.well-known/agent.json`
- nonce 防重放
- metadata 缓存

## 安装

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
pytest
```

## 最小使用方式

```python
from agent_auth_sdk import AgentInstance

agent = AgentInstance.create(
    domain="agent-a.example.com",
    name="weather",
    organization="A",
    endpoint="https://agent-a.example.com/invoke",
    capabilities=["publish", "sign", "verify"],
)

agent.save_keys("runtime/keys")
agent.export_metadata("runtime")
```

发布到中心 registry：

```python
await agent.publish(
    registry_url="http://192.144.228.237/registry/agents",
    publisher="developer-a",
    token="your-registry-token",
)
```

## CLI

生成密钥：

```bash
agent-auth-sdk keygen
```

渲染 metadata：

```bash
agent-auth-sdk render-metadata --host demo.example.com --agent-name weather --endpoint https://demo.example.com/invoke --public-key-pem-path runtime/keys/public_key.pem
```

发布到中心 registry：

```bash
agent-auth-sdk publish-to-registry --metadata-path runtime/.well-known/agent.json --registry-url http://192.144.228.237/registry/agents --token your-registry-token
```

从中心仓库解析：

```bash
agent-auth-sdk inspect-metadata agent://demo.example.com/weather --registry-url http://192.144.228.237/.well-known/agent.json
```

## 启动 registry 服务

```bash
set AGENT_REGISTRY_PATH=runtime/registry/.well-known/agent.json
set AGENT_REGISTRY_PORT=8008
python -m agent_auth_registry.run
```

## 测试

```bash
pytest
```

## 部署

CentOS 部署方案见 [deploy/DEPLOY_BETA_V1.md]。
