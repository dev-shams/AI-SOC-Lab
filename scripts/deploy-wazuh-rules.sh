#!/usr/bin/env bash
# Deploy the lab's custom Wazuh rules into the running manager.
#
# Wazuh reads user rules from /var/ossec/etc/rules/ inside the manager
# container. That path lives on a Docker volume, so the file must be copied in
# and the manager restarted; editing the repo copy alone changes nothing.
#
# The verification step matters: a silently-failed copy cost a long debugging
# session once, because the repo file was correct while the container still
# held an older version.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="$PROJECT_ROOT/Detections/wazuh-rules/local_rules.xml"
CONTAINER="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"

[ -f "$RULES" ] || { echo "Rules file not found: $RULES" >&2; exit 1; }

echo "==> Validating XML"
python3 -c "import xml.etree.ElementTree as ET,sys; r=ET.parse('$RULES').getroot(); print(f'    {len(r.findall(\"rule\"))} rules, well-formed')"

echo "==> Copying into $CONTAINER"
docker cp "$RULES" "$CONTAINER:/var/ossec/etc/rules/local_rules.xml"
docker exec "$CONTAINER" sh -c 'chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml; chmod 660 /var/ossec/etc/rules/local_rules.xml'

echo "==> Verifying the container actually has it"
LOCAL_SUM=$(shasum -a 256 "$RULES" | cut -d' ' -f1)
REMOTE_SUM=$(docker exec "$CONTAINER" sh -c 'sha256sum /var/ossec/etc/rules/local_rules.xml' | cut -d' ' -f1)
if [ "$LOCAL_SUM" != "$REMOTE_SUM" ]; then
  echo "    MISMATCH: the copy did not land. Aborting." >&2
  exit 1
fi
echo "    checksums match"

echo "==> Restarting manager"
docker restart "$CONTAINER" >/dev/null
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"' 2>/dev/null; then
    echo "    analysisd running"
    break
  fi
  sleep 5
done

cat <<'NOTE'

==> Done. If analysisd failed to start, the ruleset did not parse:
      docker logs single-node-wazuh.manager-1 | tail -30

    Confirm the rules are loaded and enabled via the manager API:
      TOKEN=$(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' \
        -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")
      curl -sk -H "Authorization: Bearer $TOKEN" \
        "https://127.0.0.1:55000/rules?rule_ids=100100,100101,100110,100120,100121"

NOTE
