# Agent Auth Registry

`verifiable-agent-auth-registry` 是 Agent Auth 的单节点身份目录：管理员分配 namespace，Agent 用 Vault key 签名发布，调用方按 Agent ID 解析当前公钥。

```bash
pip install "verifiable-agent-auth-registry==1.1.0"
export AGENT_REGISTRY_STRICT_IDENTITIES=0
export AGENT_REGISTRY_URL=http://127.0.0.1:8008
export AGENT_REGISTRY_DB_PATH=$PWD/registry.sqlite3
agent-auth-registry
```

另一个终端：

```bash
export AGENT_REGISTRY_DB_PATH=$PWD/registry.sqlite3
agent-auth-registry-admin developer add \
  --client-id local --domain 127.0.0.1 --path-prefix /agents
curl --fail http://127.0.0.1:8008/health/ready
```

生产环境必须使用专用非 root 用户、单 worker、本地 SQLite、loopback Uvicorn 和 HTTPS 反向代理。Registry 只公开 live、ready、resolve、well-known 和统一 mutation 五个路由。

完整配置、systemd/Nginx、developer/namespace 管理、备份和排障见 [Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)。

License: MIT
