# Registry Beta v1 部署

Registry v1 仅支持单节点、单 worker SQLite，并且只应监听 loopback。

## 安装

```bash
export AGENT_REGISTRY_SERVER_NAME=registry.example.com
export AGENT_REGISTRY_TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem
export AGENT_REGISTRY_TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem
sudo -E bash /opt/agent_auth_sdk/deploy/deploy-registry.sh
```

缺少有效 TLS 参数时，脚本不会安装公网 Nginx 入口。

## Developer 与 namespace

```bash
source /opt/agent_auth_sdk/.venv/bin/activate
agent-auth-registry-admin create-developer --client-id developer-a
agent-auth-registry-admin grant-namespace \
  --client-id developer-a \
  --domain agents.example.com \
  --path-prefix /team-a
```

保存仅显示一次的 API key。日后使用 `rotate-api-key` 轮换。

## 运维

```bash
sudo systemctl status agent-auth-registry
sudo journalctl -u agent-auth-registry -f
curl --fail https://registry.example.com/healthz
```

备份时停服复制 SQLite 文件，或使用 SQLite backup API。不要在写入期间直接复制数据库。

完整说明见 [`docs/REGISTRY_OPERATIONS.md`](../docs/REGISTRY_OPERATIONS.md)。
