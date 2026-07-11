# Registry 部署与运维手册

本文适用于 `verifiable-agent-auth-registry 0.2.0b1`。

## 1. 支持边界

- 单节点、单 Uvicorn worker、一个 SQLite 数据库。
- 进程只监听 loopback，由 Nginx 提供公网 HTTPS。
- 不支持多 worker、HA、共享网络文件系统或在线 schema downgrade。
- Registry 管理员是 namespace 信任根；分配前必须通过组织流程确认 domain 归属。
- 默认 strict identities，拒绝 IP、localhost、`.local` 和 `.internal`。

## 2. 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_REGISTRY_HOST` | `127.0.0.1` | 生产保持 loopback |
| `AGENT_REGISTRY_PORT` | `8008` | Uvicorn 监听端口 |
| `AGENT_REGISTRY_DB_PATH` | `runtime/registry/registry.sqlite3` | SQLite 数据库 |
| `AGENT_REGISTRY_PATH` | `runtime/registry/.well-known/agent.json` | 导出缓存；HTTP 读取仍以数据库为准 |
| `AGENT_REGISTRY_ALLOWED_SKEW_SECONDS` | `300` | 写请求 timestamp 偏差 |
| `AGENT_REGISTRY_WORKERS` | `1` | 其他值直接拒绝启动 |
| `AGENT_REGISTRY_STRICT_IDENTITIES` | `1` | 生产保持开启 |

服务启用 SQLite WAL、foreign keys、busy timeout 和 schema version。写操作在 `BEGIN IMMEDIATE` 中原子提交 nonce、ownership、metadata/key 状态和成功审计。

## 3. 本地开发

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install "verifiable-agent-auth-registry==0.2.0b1"

export AGENT_REGISTRY_DB_PATH="$PWD/runtime/registry.sqlite3"
export AGENT_REGISTRY_PATH="$PWD/runtime/.well-known/agent.json"
export AGENT_REGISTRY_STRICT_IDENTITIES=0
agent-auth-registry --host 127.0.0.1 --port 8008 --workers 1
```

另一个终端：

```bash
export AGENT_REGISTRY_DB_PATH="$PWD/runtime/registry.sqlite3"
export AGENT_REGISTRY_PATH="$PWD/runtime/.well-known/agent.json"
agent-auth-registry-admin create-developer --client-id local-dev
agent-auth-registry-admin grant-namespace \
  --client-id local-dev --domain 127.0.0.1:9001 --path-prefix /
curl --fail http://127.0.0.1:8008/healthz
```

不要把该模式暴露到公网。

## 4. 生产安装

以下命令适用于 systemd Linux。Ubuntu/Debian 安装 `python3-venv nginx sqlite3`；RHEL/OpenCloudOS/CentOS 安装对应的 Python 3.11+、Nginx 和 SQLite 包。

```bash
sudo useradd --system --home-dir /opt/agent_auth_sdk/runtime --shell /usr/sbin/nologin agent-auth
sudo install -d -o agent-auth -g agent-auth -m 0700 /opt/agent_auth_sdk/runtime/registry
sudo install -d -o root -g root -m 0755 /opt/agent_auth_sdk
sudo python3 -m venv /opt/agent_auth_sdk/.venv
sudo /opt/agent_auth_sdk/.venv/bin/pip install --upgrade pip
sudo /opt/agent_auth_sdk/.venv/bin/pip install "verifiable-agent-auth-registry==0.2.0b1"
sudo install -d -o root -g root -m 0755 /etc/agent-auth
```

创建 `/etc/agent-auth/registry.env`：

```ini
AGENT_REGISTRY_HOST=127.0.0.1
AGENT_REGISTRY_PORT=8008
AGENT_REGISTRY_DB_PATH=/opt/agent_auth_sdk/runtime/registry/registry.sqlite3
AGENT_REGISTRY_PATH=/opt/agent_auth_sdk/runtime/registry/.well-known/agent.json
AGENT_REGISTRY_ALLOWED_SKEW_SECONDS=300
AGENT_REGISTRY_WORKERS=1
AGENT_REGISTRY_STRICT_IDENTITIES=1
```

```bash
sudo chmod 0600 /etc/agent-auth/registry.env
```

systemd unit 使用仓库中的 [`deploy/registry.service`](../deploy/registry.service)，包含非 root 用户、`NoNewPrivileges`、只读系统、PrivateTmp 和 capability 清空：

```bash
sudo cp deploy/registry.service /etc/systemd/system/agent-auth-registry.service
sudo systemctl daemon-reload
sudo systemctl enable --now agent-auth-registry
sudo systemctl status agent-auth-registry
curl --fail http://127.0.0.1:8008/healthz
```

如果安装路径不同，先修改 unit 中的 `WorkingDirectory`、`EnvironmentFile`、`ExecStart` 和 `ReadWritePaths`。

## 5. Nginx HTTPS

使用仓库的 [`deploy/nginx.agent-auth.conf`](../deploy/nginx.agent-auth.conf)，替换域名和证书路径后：

```bash
sudo nginx -t
sudo systemctl reload nginx
curl --fail https://registry.example.com/healthz
```

配置包含：

- HTTP 到 HTTPS 重定向、TLS 1.2/1.3 和 HSTS。
- 512 KiB body limit、安全 headers。
- 写端点 rate limit。
- 上游固定 `127.0.0.1:8008`。
- 转发原 Host、`X-Forwarded-For`、`X-Forwarded-Proto` 和 Authorization。

`agent-auth-registry` 只信任来自 `127.0.0.1` 的 forwarded headers，因此 Nginx 与服务应在同一主机。不要直接监听 `0.0.0.0`。

## 6. 一键脚本

脚本适用于已把仓库放到 `/opt/agent_auth_sdk` 的 systemd 主机：

```bash
export AGENT_AUTH_VERSION=0.2.0b1
export AGENT_AUTH_INSTALL_MODE=pypi
export AGENT_REGISTRY_SERVER_NAME=registry.example.com
export AGENT_REGISTRY_TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem
export AGENT_REGISTRY_TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem
sudo -E bash deploy/deploy-registry.sh
```

`AGENT_AUTH_INSTALL_MODE=source` 才会 editable-install 当前源码。`--purge` 会删除数据库、导出缓存和 venv，只能在明确需要重建时使用。

## 7. Developer 与 namespace

admin CLI 必须加载与服务相同的数据库路径：

```bash
set -a
source /etc/agent-auth/registry.env
set +a
source /opt/agent_auth_sdk/.venv/bin/activate
```

| 命令 | 作用 |
|---|---|
| `create-developer --client-id ID` | 创建 developer；API key 只显示一次 |
| `list-developers` | 列出 developer 状态，不返回 API key |
| `grant-namespace --client-id ID --domain DOMAIN --path-prefix PATH` | 分配不重叠 namespace |
| `list-namespaces [--client-id ID]` | 查询 namespace id/status |
| `revoke-namespace --namespace-id ID` | 撤销 namespace；不自动撤销已发布 Agent |
| `rotate-api-key --client-id ID` | 使旧 API key 立即失效，新 key 只显示一次 |
| `revoke-developer --client-id ID` | 禁止 developer 后续写操作 |
| `inspect-agent --agent-id ID` | 查询 ownership 和 Registry entry |
| `revoke-agent --agent-id ID` | 管理员不可逆撤销 Agent |

每个 admin 命令都接受可选 `--db-path PATH`；生产更推荐统一加载 `AGENT_REGISTRY_DB_PATH`，避免误操作另一个数据库。

namespace 使用规范化后的精确 domain 和 path 前缀；有效 namespace 不能跨 developer 重叠。

## 8. HTTP API

### 公开读取

| 端点 | 成功响应 | 缓存 |
|---|---|---|
| `GET /healthz` | `{"status":"ok"}`；数据库不可写时 503 | 无 |
| `GET /.well-known/agent.json` | `AgentRegistryDocument` | ETag，60 秒 |
| `GET /v1/agents/resolve?agent_id=...` | `{agent_id, metadata}` | ETag，60 秒 |

resolve 对无效 identity 返回 400，对不存在或已撤销 Agent 返回 404。

### 签名写入

| 端点 | SDK 方法 | 语义 |
|---|---|---|
| `POST /v1/agents/publish` | `RegistryClient.publish` | 首次 insert ownership；同 owner 更新 metadata |
| `POST /v1/agents/rotate-key` | `rotate_key` | 新 key 成为 current，旧 current inactive |
| `POST /v1/agents/add-key` | `add_key` | 增加 active key，不改变 current |
| `POST /v1/agents/revoke-key` | `revoke_key` | 永久撤销非 current kid |
| `POST /v1/agents/revoke` | `revoke_agent` | 不可逆撤销整个 Agent |

写请求要求 developer Bearer API key、`x-registry-client-id` 和 Agent 签名 headers。publish 的 header/body/metadata agent_id 必须一致；rotate/add 同时要求新 key possession proof。应用应使用 SDK，不要手写 canonical 请求。

| 端点 | Request body | 成功响应关键字段 |
|---|---|---|
| publish | `agent_id`, `metadata`, `publish_intent="upsert_metadata"` | `ok`, `agent_id`, `developer_id`, `client_id` |
| rotate-key | `agent_id`, `new_key`, `new_key_proof_headers` | `ok`, `agent_id`, `current_kid` |
| add-key | `agent_id`, `new_key`, `new_key_proof_headers` | `ok`, `agent_id`, `added_kid` |
| revoke-key | `agent_id`, `kid_to_revoke` | `ok`, `agent_id`, `revoked_kid` |
| revoke | `agent_id` | `ok`, `agent_id` |

共同签名 headers 为 `Authorization: Bearer ...`、`x-registry-client-id`、`x-agent-id`、`x-agent-kid`、`x-agent-timestamp`、`x-agent-nonce`、`x-agent-signature`、`x-agent-signature-input` 和 `host`。rotate/add 的 body 还包含由新 key 生成的 proof headers。

常见状态：400 输入/证明错误，401 API key 或签名失败，403 namespace/owner 不允许，404 Agent/key 不存在，409 ownership 或并发状态冲突，422 schema 错误。

旧 `/registry/agents/*` 路径仅保留 beta 兼容，新客户端不得使用。

## 9. 备份与恢复

在线备份使用 SQLite backup command：

```bash
sudo -u agent-auth sqlite3 /opt/agent_auth_sdk/runtime/registry/registry.sqlite3 \
  ".backup '/opt/agent_auth_sdk/runtime/registry/backup-$(date +%Y%m%d-%H%M%S).sqlite3'"
```

或者停服后复制数据库：

```bash
sudo systemctl stop agent-auth-registry
sudo cp --preserve=mode,ownership,timestamps \
  /opt/agent_auth_sdk/runtime/registry/registry.sqlite3 \
  /secure-backup/registry.sqlite3
sudo systemctl start agent-auth-registry
```

不要在活跃写入时只复制主 `.sqlite3` 文件而忽略 WAL。恢复前停服、备份当前文件、复制已验证的备份、修正 owner/mode，再启动并检查 `/healthz` 和已知 agent resolve。

## 10. 升级与回滚

```bash
sudo systemctl stop agent-auth-registry
# 先执行第 9 节备份
sudo /opt/agent_auth_sdk/.venv/bin/pip install --upgrade \
  "verifiable-agent-auth-registry==0.2.0b1"
sudo systemctl start agent-auth-registry
curl --fail https://registry.example.com/healthz
```

两个发行包必须使用 Registry 声明的精确配套版本。升级前阅读 CHANGELOG。若未来版本包含 schema migration，不得仅降级 Python 包后复用已迁移数据库；按发布说明恢复备份。

## 11. 监控与排障

```bash
sudo journalctl -u agent-auth-registry -f
sudo systemctl show agent-auth-registry -p User -p MainPID
curl -i https://registry.example.com/healthz
curl -i https://registry.example.com/.well-known/agent.json
```

| 现象 | 检查 |
|---|---|
| 启动提示 exactly one worker | `AGENT_REGISTRY_WORKERS=1`，不要使用 Gunicorn 多 worker |
| `/healthz` 503 | DB 目录 owner/mode、磁盘空间、只读挂载、SQLite 锁 |
| publish 403 | developer 状态、domain/path namespace、三个 agent_id 是否一致 |
| publish 409 | identity 已由其他 developer 拥有，或客户端基于过期状态写入 |
| timestamp expired | 主机 NTP 和 allowed skew |
| Nginx 413/429 | body limit 或写 rate limit；不要盲目放宽 |
| admin 看不到服务数据 | admin shell 未加载与服务相同的 `AGENT_REGISTRY_DB_PATH` |

日志和审计不得输出 raw API key。认证失败也会进入 Registry 审计记录。
