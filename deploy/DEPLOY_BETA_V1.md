# Registry 部署说明

在 CentOS / OpenCloudOS 服务器上部署 Agent Auth Registry。

## 前置条件

- Python ≥ 3.11
- Nginx（可选，用于反向代理）
- `curl`、`git`

## 一键部署

```bash
# 将项目放到 /opt/agent_auth_sdk 后：
sudo bash /opt/agent_auth_sdk/deploy/deploy-registry.sh

# 如需完全清除旧数据后重装：
sudo bash /opt/agent_auth_sdk/deploy/deploy-registry.sh --purge
```

脚本自动完成：停止旧服务 → 安装依赖 → 创建运行时目录 → 写环境文件 → 安装 systemd 服务 → 启动 → 更新 Nginx → 健康检查。

## 创建 Developer 凭证

```bash
source /opt/agent_auth_sdk/.venv/bin/activate
agent-auth-registry-admin create-developer --client-id <your-client-id>

# 保存输出的 api_key，交给对应开发者
```

## 环境变量

自动写入 `/etc/agent-auth/registry.env`：

| 变量 | 默认值 |
|------|--------|
| `AGENT_REGISTRY_HOST` | `127.0.0.1` |
| `AGENT_REGISTRY_PORT` | `8008` |
| `AGENT_REGISTRY_DB_PATH` | `/opt/agent_auth_sdk/runtime/registry/registry.sqlite3` |
| `AGENT_REGISTRY_PATH` | `…/runtime/registry/.well-known/agent.json` |
| `AGENT_REGISTRY_ALLOWED_SKEW_SECONDS` | `300` |

## 公开端点

| 端点 | 用途 |
|------|------|
| `GET /.well-known/agent.json` | 注册表公开文档 |
| `POST /registry/agents/publish` | 发布 / 更新 Agent metadata |
| `POST /registry/agents/rotate-key` | 轮换密钥 |
| `POST /registry/agents/add-key` | 添加额外活跃密钥 |
| `POST /registry/agents/revoke-key` | 撤销密钥 |
| `POST /registry/agents/revoke` | 撤销 Agent（不可逆） |

## 日常运维

```bash
# 查看状态
sudo systemctl status agent-auth-registry

# 查看日志
sudo journalctl -u agent-auth-registry -f

# 重启
sudo systemctl restart agent-auth-registry

# 查看已注册 developer
agent-auth-registry-admin list-developers

# 查看 Agent owner
agent-auth-registry-admin inspect-agent --agent-id agent://<host>/<name>
```

## 备份

需要备份两个文件：

- `/opt/agent_auth_sdk/runtime/registry/registry.sqlite3`
- `/opt/agent_auth_sdk/runtime/registry/.well-known/agent.json`
