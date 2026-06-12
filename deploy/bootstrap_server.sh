#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/agent_auth_sdk
SERVICE_USER=agentauth

sudo useradd --system --create-home --home-dir "$APP_DIR" --shell /sbin/nologin "$SERVICE_USER" 2>/dev/null || true
sudo mkdir -p "$APP_DIR" /etc/agent-auth
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

cd "$APP_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .[dev]

mkdir -p runtime/registry/.well-known

echo "Bootstrap finished."
echo "Next:"
echo "1. Copy deploy/registry.env.example to /etc/agent-auth/registry.env and edit it."
echo "2. Install deploy/registry.service into /etc/systemd/system/."
echo "3. Install deploy/nginx.agent-auth.conf into /etc/nginx/conf.d/."
