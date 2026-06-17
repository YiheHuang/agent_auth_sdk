#!/usr/bin/env bash
# ===========================================================================
# Agent Auth Registry — 一键部署 / 升级脚本
# 适用于 CentOS / OpenCloudOS，以 root 运行
#
# 用法:
#   sudo bash deploy/deploy-registry.sh              # 全新部署或升级
#   sudo bash deploy/deploy-registry.sh --purge      # 完全清除后重新部署
# ===========================================================================
set -euo pipefail

# ── 配置 ────────────────────────────────────────────────────────────────────
PROJECT_DIR="/opt/agent_auth_sdk"
VENV_DIR="$PROJECT_DIR/.venv"
RUNTIME_DIR="$PROJECT_DIR/runtime/registry"
DB_PATH="$RUNTIME_DIR/registry.sqlite3"
PUBLIC_PATH="$RUNTIME_DIR/.well-known/agent.json"
ENV_FILE="/etc/agent-auth/registry.env"
SERVICE_NAME="agent-auth-registry"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NGINX_CONF="/etc/nginx/conf.d/agent-auth.conf"
ALLOWED_SKEW="${AGENT_REGISTRY_ALLOWED_SKEW_SECONDS:-300}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${RED}==>${NC} $*"; }

# ── 参数解析 ────────────────────────────────────────────────────────────────
PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
    PURGE=true
fi

# ── 停止旧服务 ──────────────────────────────────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    log "停止 $SERVICE_NAME ..."
    systemctl stop "$SERVICE_NAME"
fi

# ── 清除（可选） ────────────────────────────────────────────────────────────
if $PURGE; then
    warn "完全清除模式：删除数据库、公开文档、venv"
    rm -rf "$DB_PATH" "$PUBLIC_PATH" "$VENV_DIR"
fi

# ── 安装 Python 依赖 ────────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    log "创建 Python venv ..."
    python3 -m venv "$VENV_DIR"
fi

log "安装 SDK（开发模式） ..."
"$VENV_DIR/bin/pip" install -q --upgrade pip
"$VENV_DIR/bin/pip" install -q -e "$PROJECT_DIR"[dev]

# ── 运行时目录 ──────────────────────────────────────────────────────────────
log "准备运行时目录 ..."
mkdir -p "$RUNTIME_DIR/.well-known"
# sqlite3 需要目录可写；因为 systemd 以 root 运行，保持 root 即可

# ── 环境文件 ────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$ENV_FILE")"
log "写入环境文件 $ENV_FILE ..."
cat > "$ENV_FILE" <<EOF
AGENT_REGISTRY_HOST=127.0.0.1
AGENT_REGISTRY_PORT=8008
AGENT_REGISTRY_DB_PATH=$DB_PATH
AGENT_REGISTRY_PATH=$PUBLIC_PATH
AGENT_REGISTRY_ALLOWED_SKEW_SECONDS=300
EOF

# systemd EnvironmentFile 需要 KEY=VALUE，bash source 需要 export 才能被子进程继承。
# 写一个辅助脚本，用户 source 它即可。两个文件放同一目录。
ENV_SH="$(dirname "$ENV_FILE")/env.sh"
cat > "$ENV_SH" <<'BASH'
#!/usr/bin/env bash
set -a
source "$(dirname "${BASH_SOURCE[0]}")/registry.env"
set +a
BASH

# 当前进程 export
set -a
source "$ENV_FILE"
set +a

# ── systemd 服务 ─────────────────────────────────────────────────────────────
log "安装 systemd 服务 ..."
cp "$PROJECT_DIR/deploy/registry.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# ── 启动服务 ─────────────────────────────────────────────────────────────────
log "启动 $SERVICE_NAME ..."
systemctl restart "$SERVICE_NAME"

# 等待就绪
log "等待服务健康检查 ..."
for i in $(seq 1 20); do
    if curl -sf http://127.0.0.1:8008/healthz >/dev/null 2>&1; then
        log "服务健康检查通过"
        break
    fi
    sleep 1
done

# ── Nginx ────────────────────────────────────────────────────────────────────
if command -v nginx &>/dev/null; then
    log "更新 Nginx 配置 ..."
    cp "$PROJECT_DIR/deploy/nginx.agent-auth.conf" "$NGINX_CONF"
    nginx -t && systemctl reload nginx
fi

# ── 最终状态 ─────────────────────────────────────────────────────────────────
echo ""
systemctl status "$SERVICE_NAME" --no-pager -l 2>/dev/null || true

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Registry 部署完成${NC}"
echo ""
echo -e "  状态:         ${CYAN}sudo systemctl status $SERVICE_NAME${NC}"
echo -e "  日志:         ${CYAN}sudo journalctl -u $SERVICE_NAME -f${NC}"
echo -e "  公开文档:     ${CYAN}http://192.144.228.237/.well-known/agent.json${NC}"
echo -e "  端点:"
echo -e "    publish:    ${CYAN}http://192.144.228.237/registry/agents/publish${NC}"
echo -e "    rotate-key: ${CYAN}http://192.144.228.237/registry/agents/rotate-key${NC}"
echo -e "    add-key:    ${CYAN}http://192.144.228.237/registry/agents/add-key${NC}"
echo -e "    revoke-key: ${CYAN}http://192.144.228.237/registry/agents/revoke-key${NC}"
echo -e "    revoke:     ${CYAN}http://192.144.228.237/registry/agents/revoke${NC}"
echo ""
echo -e "  创建 developer:"
echo -e "    ${CYAN}source $ENV_SH${NC}"
echo -e "    ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo -e "    ${CYAN}agent-auth-registry-admin create-developer --client-id <your-client-id>${NC}"
echo -e "    ${CYAN}agent-auth-registry-admin list-developers${NC}"
echo ""
echo -e "  ${RED}⚠ 每次 admin 命令前必须先 source $ENV_SH${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
