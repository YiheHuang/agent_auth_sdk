# Agent Auth Registry 运维

## 支持范围

Registry v1 是单节点、单 worker SQLite 服务。若需要多实例或 HA，应等待 Postgres backend，不得直接增加 Uvicorn worker。

默认 `AGENT_REGISTRY_STRICT_IDENTITIES=1`，拒绝 IP、localhost、`.local` 和 `.internal` 身份。仅本机测试环境可以显式设为 `0`。

## 初始化

```bash
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin grant-namespace --client-id developer-a --domain agents.example.com --path-prefix /team-a
agent-auth-registry-admin list-namespaces --client-id developer-a
```

API key 只在创建或轮换时输出一次：

```bash
agent-auth-registry-admin rotate-api-key --client-id developer-a
```

## 端点

- `GET /healthz`：数据库读写就绪检查。
- `GET /.well-known/agent.json`：聚合目录和稳定 ETag。
- `GET /v1/agents/resolve?agent_id=...`：单 Agent metadata。
- `POST /v1/agents/publish|rotate-key|add-key|revoke-key|revoke`：签名写操作。

旧 `/registry/agents/*` 路径仅保留 beta 兼容，不应出现在新客户端配置中。

## SQLite

服务启用 WAL、foreign keys、busy timeout 和 schema version。写操作通过 `BEGIN IMMEDIATE` 原子提交 nonce、Agent 状态和成功审计，并用状态版本条件拒绝并发的过期更新。

备份时使用 SQLite backup API 或停服后复制数据库；不要在活跃写入期间直接复制单个数据库文件。

## 部署

服务只监听 `127.0.0.1`，由 HTTPS Nginx 反向代理。systemd 使用专用 `agent-auth` 用户和只读系统保护。部署前配置：

```bash
export AGENT_REGISTRY_SERVER_NAME=registry.example.com
export AGENT_REGISTRY_TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem
export AGENT_REGISTRY_TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem
sudo -E bash deploy/deploy-registry.sh
```

未提供有效 TLS 配置时，脚本不会创建公网 Nginx 入口。
