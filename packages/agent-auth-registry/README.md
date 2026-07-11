# Agent Auth Registry

`verifiable-agent-auth-registry` 是 Agent Auth 的中心身份 Registry，提供 developer namespace、Agent metadata 发布、公钥解析、密钥生命周期、原子 nonce 防重放和审计。

当前版本：`0.2.0b1`。Registry v1 只支持单节点、单 worker SQLite，并且必须放在 HTTPS 反向代理之后。

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
pip install "verifiable-agent-auth-registry==0.2.0b1"
```

本地测试：

```bash
export AGENT_REGISTRY_DB_PATH="$PWD/runtime/registry.sqlite3"
export AGENT_REGISTRY_PATH="$PWD/runtime/.well-known/agent.json"
export AGENT_REGISTRY_STRICT_IDENTITIES=0
agent-auth-registry --host 127.0.0.1 --port 8008 --workers 1
```

`STRICT_IDENTITIES=0` 允许 IP/localhost identity，只能用于本机测试。

## 管理员初始化

```bash
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin grant-namespace \
  --client-id developer-a \
  --domain agents.example.com \
  --path-prefix /team-a
agent-auth-registry-admin list-namespaces --client-id developer-a
```

API key 只在创建和轮换时显示一次。admin CLI 必须读取与服务相同的 `AGENT_REGISTRY_DB_PATH`。

## HTTP 端点

- `GET /healthz`
- `GET /.well-known/agent.json`
- `GET /v1/agents/resolve?agent_id=...`
- `POST /v1/agents/publish`
- `POST /v1/agents/rotate-key`
- `POST /v1/agents/add-key`
- `POST /v1/agents/revoke-key`
- `POST /v1/agents/revoke`

应用应使用 SDK `RegistryClient` 调用签名写端点，不应自行拼装 canonical 请求。

## 完整文档

- [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)
- [Quick Start](https://github.com/YiheHuang/agent_auth_sdk/blob/main/QUICKSTART.md)
- [公开 API Reference](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/API_REFERENCE.md)
- [安全模型](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/SECURITY_MODEL.md)
- [源码仓库](https://github.com/YiheHuang/agent_auth_sdk)

## License

MIT
