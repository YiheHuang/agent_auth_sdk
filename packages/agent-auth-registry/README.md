# Agent Auth Registry

`verifiable-agent-auth-registry` 是 Agent Auth 的轻量中心 Registry：管理员给 developer 分配
domain/path namespace，developer 发布 Agent 公钥，接收方按 agent_id 解析公钥。

`1.0.0rc1` 正式支持单节点、单 worker SQLite。它不支持 HA，也不应直接暴露 Uvicorn 到公网。

## 安装和运行

```bash
python -m venv .venv
source .venv/bin/activate
pip install "verifiable-agent-auth-registry==1.0.0rc1"

export AGENT_REGISTRY_DB_PATH="$PWD/runtime/registry.sqlite3"
agent-auth-registry --host 127.0.0.1 --port 8008 --workers 1
```

生产环境必须放在 HTTPS Nginx 后，并使用专用非 root 用户。

## 初始化

```bash
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin grant-namespace \
  --client-id developer-a \
  --domain agents.example.com \
  --path-prefix /team-a
```

API key 只显示一次。Admin CLI 必须读取与服务相同的 `AGENT_REGISTRY_DB_PATH`。

## 检查和备份

```bash
agent-auth-registry-admin db check
agent-auth-registry-admin db backup --output /secure-backup/registry.sqlite3
curl --fail http://127.0.0.1:8008/health/ready
```

## HTTP API

- `GET /health/live`
- `GET /health/ready`
- `GET /.well-known/agent.json`
- `GET /v1/agents/resolve?agent_id=...`
- `POST /v1/agents/publish`
- `POST /v1/agents/rotate-key`
- `POST /v1/agents/add-key`
- `POST /v1/agents/revoke-key`
- `POST /v1/agents/revoke`

签名写操作应通过 SDK `RegistryClient`，不要在应用中手工拼 canonical 请求。

完整部署、Nginx、systemd、备份恢复和排障见
[Registry 部署与运维](https://github.com/YiheHuang/agent_auth_sdk/blob/main/docs/REGISTRY_OPERATIONS.md)。

License: MIT
