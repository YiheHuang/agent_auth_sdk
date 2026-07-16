# Registry 部署与运维

适用于 `verifiable-agent-auth-registry==1.1.0`。Registry 只支持单节点、单 worker、本地 SQLite；不要使用 Gunicorn 多 worker、共享文件系统或直接暴露 Uvicorn。

## 配置

| 环境变量 | 生产值 | 说明 |
|---|---|---|
| `AGENT_REGISTRY_URL` | `https://registry.example.com` | 必填；必须与 SDK 配置完全一致，也是 mutation audience |
| `AGENT_REGISTRY_HOST` | `127.0.0.1` | 不要改为公网监听 |
| `AGENT_REGISTRY_PORT` | `8008` | loopback 端口 |
| `AGENT_REGISTRY_DB_PATH` | `/var/lib/agent-auth/registry.sqlite3` | 持久化本地磁盘 |
| `AGENT_REGISTRY_ALLOWED_SKEW_SECONDS` | `120` | 签名时间容差 |
| `AGENT_REGISTRY_STRICT_IDENTITIES` | `1` | 生产必须开启 |

## 本地开发

```bash
pip install "verifiable-agent-auth-registry==1.1.0"
export AGENT_REGISTRY_STRICT_IDENTITIES=0
export AGENT_REGISTRY_URL=http://127.0.0.1:8008
export AGENT_REGISTRY_DB_PATH=$PWD/registry.sqlite3
agent-auth-registry
```

不要把该模式暴露到公网。

## Linux 生产部署

Ubuntu/Debian 安装 Python 3.11+、`python3-venv`、Nginx；RHEL 系安装等价软件包。然后：

```bash
sudo useradd --system --home-dir /var/lib/agent-auth --shell /usr/sbin/nologin agent-auth
sudo install -d -o agent-auth -g agent-auth -m 0700 /var/lib/agent-auth
sudo install -d -o root -g root -m 0755 /opt/agent-auth /etc/agent-auth
sudo python3 -m venv /opt/agent-auth/venv
sudo /opt/agent-auth/venv/bin/pip install "verifiable-agent-auth-registry==1.1.0"
```

将 [`deploy/registry.env.example`](../deploy/registry.env.example) 安装为 `/etc/agent-auth/registry.env`，填入公开 HTTPS URL 后设为 `0600`。将 [`deploy/registry.service`](../deploy/registry.service) 安装到 `/etc/systemd/system/agent-auth-registry.service`：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now agent-auth-registry
curl --fail http://127.0.0.1:8008/health/ready
```

将 [`deploy/nginx.agent-auth.conf`](../deploy/nginx.agent-auth.conf) 中的域名和证书路径替换为真实值，再执行 `nginx -t && systemctl reload nginx`。配置只代理五个公开路由，限制写速率和请求体，并启用 TLS 1.2/1.3。证书申请与续期由站点既有 ACME 流程负责。

仓库脚本 `sudo -E bash deploy/deploy-registry.sh` 可执行上述固定版本安装；`AGENT_AUTH_INSTALL_MODE=source` 才使用源码。`--purge` 会删除 Registry 数据库和 venv，执行前必须备份。

## 管理员 CLI

所有命令必须读取与服务相同的 `AGENT_REGISTRY_DB_PATH`：

```bash
set -a; source /etc/agent-auth/registry.env; set +a
source /opt/agent-auth/venv/bin/activate

agent-auth-registry-admin developer add \
  --client-id my-team --domain agents.example.com --path-prefix /team
agent-auth-registry-admin developer list
agent-auth-registry-admin developer rotate-key --client-id my-team
agent-auth-registry-admin developer revoke --client-id my-team

agent-auth-registry-admin namespace grant \
  --client-id my-team --domain agents.example.com --path-prefix /other
agent-auth-registry-admin namespace list --client-id my-team
agent-auth-registry-admin namespace revoke --namespace-id UUID

agent-auth-registry-admin agent revoke --agent-id agent://agents.example.com/team/a
agent-auth-registry-admin db check
agent-auth-registry-admin db backup --output /secure/registry.sqlite3
```

API key 只显示一次。有效 namespace 不能重叠；Agent revoke 不可逆。

## HTTP API

Registry 恰好公开五个路由：

| 路由 | 说明 |
|---|---|
| `GET /health/live` | 进程存活 |
| `GET /health/ready` | schema、integrity 和数据库写就绪；失败为 503 |
| `GET /v1/agents/resolve?agent_id=...` | 单 Agent 最小 metadata，支持 ETag |
| `GET /.well-known/agent.json` | 所有活跃 Agent 目录，支持 ETag |
| `POST /v1/agents` | SignedEnvelope mutation |

写请求同时要求 `Authorization: Bearer <developer-api-key>` 和 `X-Registry-Client-ID`。envelope `type` 只能为 `registry.publish`、`registry.rotate` 或 `registry.revoke`。应用使用 `agent-auth publish/rotate/revoke`，无需手写协议。

常见状态码：400 输入错误，401 developer/签名失败，403 namespace/owner 越权，404 未找到，409 重放、kid 或状态冲突。

## 备份、升级与恢复

优先使用在线备份：

```bash
agent-auth-registry-admin db check
agent-auth-registry-admin db backup --output /secure/registry-$(date +%F-%H%M).sqlite3
```

恢复时停服，保留当前数据库，复制已验证备份，修正 `agent-auth:agent-auth` owner 和 `0600` 权限，再启动并检查 ready/resolve。不要在运行时只复制主 SQLite 文件而忽略 WAL。

1.0 按全新 schema 处理，不迁移 beta 数据。升级前备份并阅读 CHANGELOG；Registry 精确依赖同版本 SDK。不要将新 schema 数据库直接用于旧二进制。

## 排障

```bash
sudo journalctl -u agent-auth-registry -f
curl -i https://registry.example.com/health/ready
curl -i "https://registry.example.com/v1/agents/resolve?agent_id=agent%3A%2F%2Fagents.example.com%2Fteam%2Fa"
```

- 启动失败：确认 `AGENT_REGISTRY_URL`、DB 目录权限和 Python 版本。
- ready 503：检查磁盘、只读挂载、SQLite integrity/lock。
- publish 403：检查 developer 状态及 domain/path namespace。
- publish 409：检查 owner、重复 request ID、kid 历史或已撤销状态。
- `AUDIENCE_MISMATCH`：Registry URL 必须和应用 TOML 字节完全一致（末尾斜杠除外）。
- `TIMESTAMP_EXPIRED`：检查两端 NTP。

审计记录认证失败和 mutation 结果，但不得记录原始 API key、signature 或 payload。
