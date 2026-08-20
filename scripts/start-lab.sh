#!/usr/bin/env bash
# Start the Wazuh stack and the AI SOC console.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK_DIR="$PROJECT_ROOT/wazuh-docker/single-node"
APP_DIR="$PROJECT_ROOT/soc-ai-platform"
PORT="${PORT:-5174}"

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker Desktop first." >&2
  exit 1
fi

if [ ! -d "$STACK_DIR" ]; then
  echo "Wazuh stack not found. Run ./scripts/setup-wazuh.sh first." >&2
  exit 1
fi

echo "==> Starting Wazuh (manager, indexer, dashboard)"
( cd "$STACK_DIR" && docker compose up -d )

echo "==> Waiting for the indexer to accept queries"
for _ in $(seq 1 60); do
  if curl -sk -u "${WAZUH_INDEXER_USER:-admin}:${WAZUH_INDEXER_PASSWORD:-SecretPassword}" \
      "${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}" >/dev/null 2>&1; then
    echo "    indexer is up"
    break
  fi
  sleep 5
done

# Load .env if present so ANTHROPIC_API_KEY reaches the console.
if [ -f "$PROJECT_ROOT/.env" ]; then
  set -a; . "$PROJECT_ROOT/.env"; set +a
  echo "==> Loaded .env"
fi

PYTHON="$APP_DIR/.venv/bin/python"
[ -x "$PYTHON" ] || PYTHON="python3"

echo "==> Wazuh dashboard: https://localhost"
echo "==> AI SOC console:  http://127.0.0.1:$PORT"
echo
PORT="$PORT" exec "$PYTHON" "$APP_DIR/server.py"
