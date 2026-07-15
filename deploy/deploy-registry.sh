#!/usr/bin/env bash
# ===========================================================================
# Agent Auth Registry — 一键部署 / 升级脚本
# 适用于 CentOS / OpenCloudOS，以 root 运行
#
# 用法:
#   sudo bash deploy/deploy-registry.sh              # 默认从 PyPI 安装固定版本
#   sudo AGENT_AUTH_INSTALL_MODE=source bash deploy/deploy-registry.sh
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
STRICT_IDENTITIES="${AGENT_REGISTRY_STRICT_IDENTITIES:-1}"
SERVER_NAME="${AGENT_REGISTRY_SERVER_NAME:-}"
TLS_CERT="${AGENT_REGISTRY_TLS_CERT:-}"
TLS_KEY="${AGENT_REGISTRY_TLS_KEY:-}"
INSTALL_MODE="${AGENT_AUTH_INSTALL_MODE:-pypi}"
AGENT_AUTH_VERSION="${AGENT_AUTH_VERSION:-1.0.0rc1}"

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

log "安装 Registry 发行依赖 ..."
"$VENV_DIR/bin/pip" install -q --upgrade pip
if [[ "$INSTALL_MODE" == "pypi" ]]; then
    "$VENV_DIR/bin/pip" install -q "verifiable-agent-auth-registry==$AGENT_AUTH_VERSION"
elif [[ "$INSTALL_MODE" == "source" ]]; then
    "$VENV_DIR/bin/pip" install -q -e "$PROJECT_DIR"
    "$VENV_DIR/bin/pip" install -q -e "$PROJECT_DIR/packages/agent-auth-registry"
else
    warn "AGENT_AUTH_INSTALL_MODE 必须是 pypi 或 source"
    exit 1
fi

# ── 运行时目录 ──────────────────────────────────────────────────────────────
log "准备运行时目录 ..."
mkdir -p "$RUNTIME_DIR/.well-known"
if ! id -u agent-auth >/dev/null 2>&1; then
    useradd --system --home-dir "$RUNTIME_DIR" --shell /sbin/nologin agent-auth
fi
chown -R agent-auth:agent-auth "$RUNTIME_DIR"
chmod 0700 "$RUNTIME_DIR"

# ── 环境文件 ────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$ENV_FILE")"
log "写入环境文件 $ENV_FILE ..."
cat > "$ENV_FILE" <<EOF
AGENT_REGISTRY_HOST=127.0.0.1
AGENT_REGISTRY_PORT=8008
AGENT_REGISTRY_DB_PATH=$DB_PATH
AGENT_REGISTRY_PATH=$PUBLIC_PATH
AGENT_REGISTRY_ALLOWED_SKEW_SECONDS=$ALLOWED_SKEW
AGENT_REGISTRY_WORKERS=1
AGENT_REGISTRY_STRICT_IDENTITIES=$STRICT_IDENTITIES
EOF
chmod 0600 "$ENV_FILE"

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
if command -v nginx &>/dev/null && [[ -n "$SERVER_NAME" && -n "$TLS_CERT" && -n "$TLS_KEY" ]]; then
    if [[ ! "$SERVER_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || [[ ! -f "$TLS_CERT" ]] || [[ ! -f "$TLS_KEY" ]]; then
        warn "Registry TLS 配置无效；拒绝安装公网 Nginx 配置"
        exit 1
    fi
    log "更新 Nginx 配置 ..."
    sed \
        -e "s/registry.example.com/$SERVER_NAME/g" \
        -e "s#/etc/letsencrypt/live/$SERVER_NAME/fullchain.pem#$TLS_CERT#g" \
        -e "s#/etc/letsencrypt/live/$SERVER_NAME/privkey.pem#$TLS_KEY#g" \
        "$PROJECT_DIR/deploy/nginx.agent-auth.conf" > "$NGINX_CONF"
    nginx -t && systemctl reload nginx
else
    warn "未配置 AGENT_REGISTRY_SERVER_NAME/TLS_CERT/TLS_KEY；Registry 仅监听 loopback，不会明文暴露"
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
PUBLIC_ORIGIN="https://${SERVER_NAME:-registry.example.com}"
echo -e "  公开文档:     ${CYAN}$PUBLIC_ORIGIN/.well-known/agent.json${NC}"
echo -e "  端点:"
echo -e "    publish:    ${CYAN}$PUBLIC_ORIGIN/v1/agents/publish${NC}"
echo -e "    rotate-key: ${CYAN}$PUBLIC_ORIGIN/v1/agents/rotate-key${NC}"
echo -e "    add-key:    ${CYAN}$PUBLIC_ORIGIN/v1/agents/add-key${NC}"
echo -e "    revoke-key: ${CYAN}$PUBLIC_ORIGIN/v1/agents/revoke-key${NC}"
echo -e "    revoke:     ${CYAN}$PUBLIC_ORIGIN/v1/agents/revoke${NC}"
echo ""
echo -e "  创建 developer:"
echo -e "    ${CYAN}source $ENV_SH${NC}"
echo -e "    ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo -e "    ${CYAN}agent-auth-registry-admin create-developer --client-id <your-client-id>${NC}"
echo -e "    ${CYAN}agent-auth-registry-admin list-developers${NC}"
echo ""
echo -e "  ${RED}⚠ 每次 admin 命令前必须先 source $ENV_SH${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
