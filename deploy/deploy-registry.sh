#!/usr/bin/env bash
set -euo pipefail

VERSION="${AGENT_AUTH_VERSION:-1.0.0}"
INSTALL_MODE="${AGENT_AUTH_INSTALL_MODE:-pypi}"
PUBLIC_URL="${AGENT_REGISTRY_URL:-}"
ROOT="/opt/agent-auth"
VENV="$ROOT/venv"
DATA="/var/lib/agent-auth"
ENV_FILE="/etc/agent-auth/registry.env"
SOURCE_DIR="${AGENT_AUTH_SOURCE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi
if [[ -z "$PUBLIC_URL" || "$PUBLIC_URL" != https://* ]]; then
    echo "Set AGENT_REGISTRY_URL to the public HTTPS Registry URL" >&2
    exit 1
fi
if [[ "${1:-}" == "--purge" ]]; then
    [[ "$DATA" == "/var/lib/agent-auth" && "$VENV" == "/opt/agent-auth/venv" ]] || exit 1
    systemctl stop agent-auth-registry 2>/dev/null || true
    rm -rf -- "$DATA" "$VENV"
fi

id agent-auth >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin agent-auth
install -d -o root -g root -m 0755 "$ROOT" /etc/agent-auth
install -d -o agent-auth -g agent-auth -m 0700 "$DATA"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
if [[ "$INSTALL_MODE" == "pypi" ]]; then
    "$VENV/bin/pip" install "verifiable-agent-auth-registry==$VERSION"
elif [[ "$INSTALL_MODE" == "source" ]]; then
    "$VENV/bin/pip" install "$SOURCE_DIR" "$SOURCE_DIR/packages/agent-auth-registry"
else
    echo "AGENT_AUTH_INSTALL_MODE must be pypi or source" >&2
    exit 1
fi

cat >"$ENV_FILE" <<EOF
AGENT_REGISTRY_URL=$PUBLIC_URL
AGENT_REGISTRY_HOST=127.0.0.1
AGENT_REGISTRY_PORT=8008
AGENT_REGISTRY_DB_PATH=$DATA/registry.sqlite3
AGENT_REGISTRY_ALLOWED_SKEW_SECONDS=${AGENT_REGISTRY_ALLOWED_SKEW_SECONDS:-120}
AGENT_REGISTRY_STRICT_IDENTITIES=${AGENT_REGISTRY_STRICT_IDENTITIES:-1}
EOF
chmod 0600 "$ENV_FILE"
install -m 0644 "$SOURCE_DIR/deploy/registry.service" /etc/systemd/system/agent-auth-registry.service
systemctl daemon-reload
systemctl enable --now agent-auth-registry

for _ in $(seq 1 20); do
    curl --fail --silent http://127.0.0.1:8008/health/ready >/dev/null && exit 0
    sleep 1
done
echo "Registry did not become ready; inspect journalctl -u agent-auth-registry" >&2
exit 1
