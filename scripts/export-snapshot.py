#!/usr/bin/env python3
"""Freeze live Wazuh alerts into a static snapshot for the hosted demo.

The console normally reads from the local Wazuh indexer. That cannot be
published: it only exists on the lab machine, and exposing a SIEM to the
internet to power a portfolio demo would be reckless. This script instead
captures a point-in-time export of real alerts, which the static build serves
when no backend is reachable.

Usage:
    python3 scripts/export-snapshot.py                  # export as-is
    python3 scripts/export-snapshot.py --anonymize      # replace the username
    python3 scripts/export-snapshot.py --minutes 10080  # widen the window

The Wazuh stack must be running. Credentials come from the same environment
variables the console uses.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = PROJECT_ROOT / "soc-ai-platform"
sys.path.insert(0, str(APP_DIR))

# A wide export asks the indexer for thousands of alerts in one request, which
# does not finish inside the console's default 8s budget. Set before importing
# server, which reads it at module load.
os.environ.setdefault("WAZUH_INDEXER_TIMEOUT", "120")

import server  # noqa: E402  (needs the path insert above)

OUTPUT = APP_DIR / "sample-data" / "snapshot.json"
PROFILES = ("candidates", "review", "raw", "noise")


def anonymize(payload, real_user):
    """Replace the lab operator's username throughout the exported JSON."""
    if not real_user:
        return payload
    text = json.dumps(payload)
    for variant in {real_user, real_user.lower(), real_user.upper()}:
        text = re.sub(re.escape(variant), "analyst", text)
    return json.loads(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minutes", type=int, default=10080, help="lookback window (default: 7 days)")
    parser.add_argument("--size", type=int, default=60, help="max alerts per queue")
    parser.add_argument(
        "--fetch",
        type=int,
        default=3000,
        help="alerts to pull from the indexer before triage (default: 3000)",
    )
    parser.add_argument("--min-level", type=int, default=4, help="minimum Wazuh rule level")
    parser.add_argument("--anonymize", action="store_true", help="replace the operator username with 'analyst'")
    parser.add_argument("--user", default="Shams", help="username to replace when --anonymize is set")
    args = parser.parse_args()

    # Deliberately not server.alerts_query(): that caps the fetch at 300 and
    # sorts newest-first, so a wide window returns only the most recent slice
    # and silently drops older candidate alerts. The snapshot needs to triage
    # the whole window, then pick the best of each queue.
    query = {
        "size": args.fetch,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": f"now-{args.minutes}m"}}},
                    {"range": {"rule.level": {"gte": args.min_level}}},
                ]
            }
        },
    }

    try:
        result = server.request_indexer("/wazuh-alerts-*/_search", query)
    except Exception as error:
        print(f"Could not reach the Wazuh indexer at {server.INDEXER_URL}: {error}", file=sys.stderr)
        print("Start the stack with ./scripts/start-lab.sh and try again.", file=sys.stderr)
        return 1

    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        print("No alerts matched. Generate telemetry with Simulations/Invoke-SocLabScenario.ps1.", file=sys.stderr)
        return 1

    alerts = [server.simplify_alert(hit) for hit in hits]
    print(f"Pulled {len(alerts)} alerts from the indexer, triaging…")
    queues = {}
    summary = {}
    for profile in PROFILES:
        visible, profile_summary = server.apply_profile(alerts, profile, args.size)
        queues[profile] = visible
        summary[profile] = profile_summary

    # Pull surrounding events for each candidate so the demo timeline is real.
    context = {}
    for alert in queues["candidates"][:10]:
        try:
            events = server.request_indexer(
                "/wazuh-alerts-*/_search", server.context_query(alert)
            )
            context[alert["id"]] = [
                server.simplify_alert(hit) for hit in events.get("hits", {}).get("hits", [])
            ]
        except Exception:
            context[alert["id"]] = []

    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "source": "Wazuh indexer export from the local AI SOC lab",
        "note": (
            "Point-in-time snapshot of real alerts from WIN11-SOC-ENDPOINT. "
            "The hosted demo serves this because the live indexer is local-only."
        ),
        "windowMinutes": args.minutes,
        "summary": summary,
        "queues": queues,
        "context": context,
    }

    if args.anonymize:
        payload = anonymize(payload, args.user)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    size_kb = OUTPUT.stat().st_size / 1024
    print(f"Wrote {OUTPUT.relative_to(PROJECT_ROOT)} ({size_kb:.0f} KB)")
    for profile in PROFILES:
        print(f"  {profile:<12} {len(queues[profile]):>3} alerts")
    print(f"  context      {sum(len(v) for v in context.values()):>3} surrounding events")
    if not args.anonymize:
        print("\nThis snapshot contains the real hostname, username, and local IP.")
        print("Re-run with --anonymize before publishing if that matters to you.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
