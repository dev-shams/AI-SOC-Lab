#!/usr/bin/env bash
# Recreate the Wazuh single-node stack from scratch.
#
# wazuh-docker/ is deliberately not committed: it is an upstream clone, and
# generating the indexer certificates writes real private keys into it. This
# script rebuilds it so a fresh clone of this repo can stand the lab back up.
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.6}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK_DIR="$PROJECT_ROOT/wazuh-docker/single-node"

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker Desktop first." >&2
  exit 1
fi

if [ ! -d "$PROJECT_ROOT/wazuh-docker" ]; then
  echo "==> Cloning wazuh-docker $WAZUH_VERSION"
  git clone --depth 1 -b "$WAZUH_VERSION" \
    https://github.com/wazuh/wazuh-docker.git "$PROJECT_ROOT/wazuh-docker"
else
  echo "==> wazuh-docker already present, skipping clone"
fi

echo "==> Raising vm.max_map_count for the indexer (OpenSearch requirement)"
docker run --rm --privileged --pid=host alpine sysctl -w vm.max_map_count=262144

if [ ! -f "$STACK_DIR/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
  echo "==> Generating indexer certificates"
  ( cd "$STACK_DIR" && docker compose -f generate-indexer-certs.yml run --rm generator )
else
  echo "==> Certificates already generated, skipping"
fi

cat <<'NOTE'

==> Setup complete.

    Start the stack with:  ./scripts/start-lab.sh

    SECURITY NOTE: this deployment ships with Wazuh's stock credentials
    (admin / SecretPassword) and the dashboard uses a self-signed certificate.
    That is acceptable for an isolated local lab and nothing else. Change the
    indexer password in wazuh-docker/single-node/docker-compose.yml before
    exposing this to any network.

NOTE
