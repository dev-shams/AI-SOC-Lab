#!/usr/bin/env bash
# Stop the Wazuh stack. Data volumes are preserved.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK_DIR="$PROJECT_ROOT/wazuh-docker/single-node"

echo "==> Stopping the AI SOC console"
pkill -f "soc-ai-platform/server.py" 2>/dev/null || true

echo "==> Stopping Wazuh containers"
( cd "$STACK_DIR" && docker compose down )

echo
echo "Wazuh data volumes are preserved. 'docker compose down -v' would delete"
echo "them along with every indexed alert; this script never does that."
