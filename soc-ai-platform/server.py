#!/usr/bin/env python3
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "SecretPassword")
DEFAULT_MIN_LEVEL = int(os.getenv("WAZUH_MIN_LEVEL", "4"))
DEFAULT_WINDOW_MINUTES = int(os.getenv("WAZUH_WINDOW_MINUTES", "120"))
RULE_PACK_PATH = Path(
    os.getenv("SOC_TRIAGE_RULE_PACK", str(ROOT / "rules" / "triage-rules.json"))
).expanduser()
NOISY_BOOT_RULES = {"61618", "61634"}
NOISY_SYSTEM_RULES = {"60642", "61104"}
ACCOUNT_SIGNAL_RULE_IDS = {"60109", "60110", "60111", "60154"}
ACCOUNT_SIGNAL_EVENT_IDS = {"4720", "4722", "4726", "4732", "4733", "4738"}
_RULE_PACK_CACHE = {"mtime_ns": None, "payload": None}


def nested(data, path, default=None):
    current = data
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def first(value, default=""):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def first_nonempty(*values, default=""):
    for value in values:
        candidate = first(value, "")
        if candidate not in (None, ""):
            return str(candidate)
    return default


def qualified_account(domain, name):
    if not name:
        return ""
    if domain and "\\" not in name:
        return f"{domain}\\{name}"
    return name


def request_indexer(path, body=None):
    url = f"{INDEXER_URL}{path}"
    headers = {"Content-Type": "application/json"}
    token = base64.b64encode(f"{INDEXER_USER}:{INDEXER_PASSWORD}".encode()).decode()
    headers["Authorization"] = f"Basic {token}"
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST" if body else "GET")
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(request, context=context, timeout=8) as response:
        return json.loads(response.read().decode())


def simplify_alert(hit):
    source = hit.get("_source", {})
    rule = source.get("rule", {})
    mitre = rule.get("mitre", {})
    win_system = nested(source, ["data", "win", "system"], {})
    win_event = nested(source, ["data", "win", "eventdata"], {})
    event_id = first_nonempty(
        win_system.get("eventID"),
        win_system.get("eventId"),
    )
    subject_user = first_nonempty(
        win_event.get("subjectUserName"),
        win_event.get("subjectUsername"),
    )
    subject_domain = first_nonempty(
        win_event.get("subjectDomainName"),
        win_event.get("subjectDomain"),
    )
    target_user = first_nonempty(
        win_event.get("targetUserName"),
        win_event.get("targetUsername"),
    )
    target_domain = first_nonempty(
        win_event.get("targetDomainName"),
        win_event.get("targetDomain"),
    )
    member_name = first_nonempty(
        win_event.get("memberName"),
        win_event.get("memberAccountName"),
    )
    member_sid = first_nonempty(
        win_event.get("memberSid"),
        win_event.get("memberSID"),
    )
    group_name = first_nonempty(
        win_event.get("groupName"),
        target_user if event_id in {"4732", "4733"} else "",
    )
    group_domain = first_nonempty(
        win_event.get("groupDomainName"),
        target_domain if event_id in {"4732", "4733"} else "",
    )
    actor = qualified_account(subject_domain, subject_user)
    account_actions = {
        "4720": "Local user account created",
        "4722": "User account enabled",
        "4726": "User account deleted",
        "4732": "Member added to local security group",
        "4733": "Member removed from local security group",
        "4738": "User account changed",
    }

    alert = {
        "id": hit.get("_id"),
        "index": hit.get("_index"),
        "timestamp": source.get("timestamp") or source.get("@timestamp", ""),
        "agent": {
            "id": nested(source, ["agent", "id"], ""),
            "name": nested(source, ["agent", "name"], ""),
            "ip": nested(source, ["agent", "ip"], ""),
        },
        "manager": nested(source, ["manager", "name"], ""),
        "rule": {
            "id": str(rule.get("id", "")),
            "level": int(rule.get("level", 0) or 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
            "mitreId": first(mitre.get("id"), ""),
            "mitreTactic": first(mitre.get("tactic"), ""),
            "mitreTechnique": first(mitre.get("technique"), ""),
        },
        "event": {
            "channel": win_system.get("channel", ""),
            "eventId": event_id,
            "provider": win_system.get("providerName", ""),
            "message": win_system.get("message", ""),
        },
        "process": {
            "image": win_event.get("image", ""),
            "parentImage": win_event.get("parentImage", ""),
            "commandLine": win_event.get("commandLine", ""),
            "parentCommandLine": win_event.get("parentCommandLine", ""),
            "currentDirectory": win_event.get("currentDirectory", ""),
            "user": first_nonempty(
                win_event.get("user"),
                actor,
                qualified_account(target_domain, target_user),
            ),
            "processId": str(win_event.get("processId", "")),
            "parentProcessId": str(win_event.get("parentProcessId", "")),
            "hashes": win_event.get("hashes", ""),
        },
        "account": {
            "action": account_actions.get(event_id, ""),
            "actor": actor,
            "actorDomain": subject_domain,
            "actorUser": subject_user,
            "targetUser": target_user,
            "targetDomain": target_domain,
            "memberName": member_name,
            "memberSid": member_sid,
            "groupName": group_name,
            "groupDomain": group_domain,
        },
    }
    alert["triage"] = triage_alert(alert)
    return alert


def normalized_text(*values):
    return " ".join(str(value or "").lower() for value in values)


def load_rule_pack():
    try:
        mtime_ns = RULE_PACK_PATH.stat().st_mtime_ns
        if (
            _RULE_PACK_CACHE["payload"] is not None
            and _RULE_PACK_CACHE["mtime_ns"] == mtime_ns
        ):
            return _RULE_PACK_CACHE["payload"]

        with RULE_PACK_PATH.open(encoding="utf-8") as rule_file:
            raw_pack = json.load(rule_file)

        rules = []
        for raw_rule in raw_pack.get("rules", []):
            if not isinstance(raw_rule, dict) or not raw_rule.get("enabled", True):
                continue
            status = raw_rule.get("status", "review")
            match = raw_rule.get("match", {})
            if (
                not raw_rule.get("id")
                or status not in {"candidate", "review", "noise"}
                or not isinstance(match, dict)
            ):
                continue
            rules.append(
                {
                    "id": str(raw_rule["id"]),
                    "title": str(raw_rule.get("title", raw_rule["id"])),
                    "status": status,
                    "score": max(0, min(int(raw_rule.get("score", 50)), 100)),
                    "reason": str(raw_rule.get("reason", raw_rule.get("title", "Rule matched"))),
                    "mitre": [str(item) for item in raw_rule.get("mitre", [])],
                    "detection": (
                        raw_rule.get("detection", {})
                        if isinstance(raw_rule.get("detection", {}), dict)
                        else {}
                    ),
                    "match": match,
                }
            )

        payload = {
            "name": str(raw_pack.get("name", RULE_PACK_PATH.stem)),
            "version": str(raw_pack.get("version", "unversioned")),
            "description": str(raw_pack.get("description", "")),
            "path": str(RULE_PACK_PATH),
            "rules": rules,
            "error": "",
        }
        _RULE_PACK_CACHE.update({"mtime_ns": mtime_ns, "payload": payload})
        return payload
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        cached = _RULE_PACK_CACHE.get("payload")
        if cached:
            return {**cached, "error": str(error)}
        return {
            "name": "Unavailable",
            "version": "0",
            "description": "",
            "path": str(RULE_PACK_PATH),
            "rules": [],
            "error": str(error),
        }


def alert_match_values(alert):
    rule = alert.get("rule", {})
    process = alert.get("process", {})
    event = alert.get("event", {})
    account = alert.get("account", {})
    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        groups = [groups]

    text = normalized_text(
        rule.get("description"),
        rule.get("id"),
        groups,
        rule.get("mitreId"),
        rule.get("mitreTactic"),
        rule.get("mitreTechnique"),
        process.get("image"),
        process.get("parentImage"),
        process.get("commandLine"),
        process.get("parentCommandLine"),
        process.get("currentDirectory"),
        process.get("user"),
        event.get("channel"),
        event.get("provider"),
        event.get("message"),
        account.get("action"),
        account.get("actor"),
        account.get("actorDomain"),
        account.get("actorUser"),
        account.get("targetUser"),
        account.get("targetDomain"),
        account.get("memberName"),
        account.get("memberSid"),
        account.get("groupName"),
        account.get("groupDomain"),
    )
    return {
        "text": text,
        "rule_id": str(rule.get("id", "")).lower(),
        "event_id": str(event.get("eventId", "")).lower(),
        "channel": str(event.get("channel", "")).lower(),
        "mitre_id": str(rule.get("mitreId", "")).lower(),
        "groups": {str(group).lower() for group in groups},
        "level": int(rule.get("level", 0) or 0),
    }


def rule_matches_alert(policy_rule, alert):
    match = policy_rule.get("match", {})
    values = alert_match_values(alert)

    any_text = [str(item).lower() for item in match.get("any_text", [])]
    all_text = [str(item).lower() for item in match.get("all_text", [])]
    exclude_text = [str(item).lower() for item in match.get("exclude_text", [])]
    if any_text and not any(item in values["text"] for item in any_text):
        return False
    if all_text and not all(item in values["text"] for item in all_text):
        return False
    if exclude_text and any(item in values["text"] for item in exclude_text):
        return False

    exact_matchers = (
        ("rule_ids", "rule_id"),
        ("event_ids", "event_id"),
        ("channels", "channel"),
        ("mitre_ids", "mitre_id"),
    )
    for rule_key, value_key in exact_matchers:
        expected = {str(item).lower() for item in match.get(rule_key, [])}
        if expected and values[value_key] not in expected:
            return False

    expected_groups = {str(item).lower() for item in match.get("groups_any", [])}
    if expected_groups and not expected_groups.intersection(values["groups"]):
        return False

    if "min_level" in match and values["level"] < int(match["min_level"]):
        return False
    if "max_level" in match and values["level"] > int(match["max_level"]):
        return False

    return any(
        key in match
        for key in (
            "any_text",
            "all_text",
            "rule_ids",
            "event_ids",
            "channels",
            "mitre_ids",
            "groups_any",
            "min_level",
            "max_level",
        )
    )


def matching_policy_rules(alert):
    matches = [
        policy_rule
        for policy_rule in load_rule_pack()["rules"]
        if rule_matches_alert(policy_rule, alert)
    ]
    return sorted(matches, key=lambda item: item["score"], reverse=True)


def is_windows_startup_noise(alert):
    rule_id = str(nested(alert, ["rule", "id"], ""))
    image = str(nested(alert, ["process", "image"], "")).lower().replace("\\\\", "\\")
    command = str(nested(alert, ["process", "commandLine"], "")).lower().replace("\\\\", "\\")
    description = str(nested(alert, ["rule", "description"], "")).lower()

    if rule_id in NOISY_SYSTEM_RULES or description == "windows system error event":
        return True

    if rule_id not in NOISY_BOOT_RULES:
        return False

    system32_processes = (
        "\\windows\\system32\\svchost.exe",
        "\\windows\\system32\\taskhost.exe",
        "\\windows\\system32\\taskhostw.exe",
        "\\windows\\system32\\backgroundtaskhost.exe",
    )
    if any(process in image for process in system32_processes):
        normal_switches = (
            "-servername:backgroundtaskhost",
            "-servername:app.",
            "-k localservicenetworkrestricted",
            "-k localsystemnetworkrestricted",
            "-k localserviceandnoimpersonation",
            "-k networkservice",
            "-k netsvcs",
            "-k wusvcs",
            "-k whesvc",
            "-k gpsvcgroup",
            "-k wsappx",
            "-s waasmedicsvc",
            "-s appxsvc",
            "-s wuauserv",
            "-s wscsvc",
            "-s whesvc",
            "-s pcasvc",
            "-s inventorysvc",
            "-s ssdpsrv",
        )
        return not command or any(switch in command for switch in normal_switches)

    return False


def is_wazuh_agent_self_check(alert):
    process = alert.get("process", {})
    text = normalized_text(
        process.get("currentDirectory"),
        process.get("commandLine"),
        process.get("parentCommandLine"),
        alert.get("event", {}).get("message"),
    ).replace("\\\\", "\\")

    return (
        "program files (x86)\\ossec-agent" in text
        and "secedit" in text
        and "secpol.cfg" in text
    ) or (
        "secedit /export /cfg" in text
        and "secpol.cfg" in text
        and "select-string" in text
        and "remove-item" in text
    )


def is_account_privilege_activity(alert):
    rule = alert.get("rule", {})
    event = alert.get("event", {})
    account = alert.get("account", {})
    rule_id = str(rule.get("id", ""))
    event_id = str(event.get("eventId", ""))
    text = normalized_text(
        rule.get("description"),
        rule.get("groups"),
        rule.get("mitreId"),
        rule.get("mitreTechnique"),
        event.get("message"),
        account.get("action"),
        account.get("actor"),
        account.get("targetUser"),
        account.get("memberName"),
        account.get("memberSid"),
        account.get("groupName"),
    )

    account_markers = (
        "soc_lab_admin",
        "user account was created",
        "user account was enabled",
        "administrators group changed",
        "a member was added to a security-enabled local group",
        "group name:\t\tadministrators",
    )

    return (
        rule_id in ACCOUNT_SIGNAL_RULE_IDS
        or event_id in ACCOUNT_SIGNAL_EVENT_IDS
        or any(marker in text for marker in account_markers)
    )


def triage_alert(alert):
    rule = alert.get("rule", {})

    if is_wazuh_agent_self_check(alert):
        return {"status": "noise", "score": 10, "reason": "Wazuh agent policy assessment self-check"}

    policy_matches = matching_policy_rules(alert)
    if policy_matches:
        primary = policy_matches[0]
        return {
            "status": primary["status"],
            "score": primary["score"],
            "reason": primary["reason"],
            "policyRule": primary["id"],
            "policyTitle": primary["title"],
            "mitre": primary["mitre"],
            "detection": primary["detection"],
            "matches": [
                {
                    "id": match["id"],
                    "title": match["title"],
                    "score": match["score"],
                    "status": match["status"],
                }
                for match in policy_matches
            ],
        }

    if is_account_privilege_activity(alert):
        return {"status": "candidate", "score": 92, "reason": "Account creation or administrator group change"}

    if is_windows_startup_noise(alert):
        return {"status": "noise", "score": 15, "reason": "Common Windows startup/background service activity"}

    if int(rule.get("level", 0) or 0) >= 12:
        return {"status": "review", "score": 65, "reason": "High Wazuh rule level, needs analyst review"}

    return {"status": "review", "score": 40, "reason": "Low or medium severity telemetry"}


def alerts_query(params):
    minutes = int(params.get("minutes", [DEFAULT_WINDOW_MINUTES])[0])
    min_level = int(params.get("min_level", [DEFAULT_MIN_LEVEL])[0])
    size = min(int(params.get("size", ["50"])[0]), 100)
    q = params.get("q", [""])[0].strip()

    must = [
        {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]

    if q:
        must.append(
            {
                "query_string": {
                    "query": f"*{q.replace('*', '').replace('?', '')}*",
                    "fields": [
                        "rule.description",
                        "rule.id",
                        "agent.name",
                        "data.win.eventdata.commandLine",
                        "data.win.eventdata.image",
                        "data.win.eventdata.subjectUserName",
                        "data.win.eventdata.targetUserName",
                        "data.win.eventdata.memberName",
                        "data.win.eventdata.groupName",
                        "data.win.system.channel",
                    ],
                    "default_operator": "AND",
                }
            }
        )

    return {
        "size": min(size * 4, 300),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
    }


def apply_profile(alerts, profile, size):
    candidates = [alert for alert in alerts if nested(alert, ["triage", "status"]) == "candidate"]
    review = [alert for alert in alerts if nested(alert, ["triage", "status"]) == "review"]
    noise = [alert for alert in alerts if nested(alert, ["triage", "status"]) == "noise"]
    if profile == "raw":
        visible = alerts[:size]
    elif profile == "review":
        visible = review[:size]
    elif profile == "noise":
        visible = noise[:size]
    elif profile == "focused":
        visible = (candidates + review)[:size]
    else:
        visible = candidates[:size]

    return visible, {
        "raw": len(alerts),
        "candidates": len(candidates),
        "review": len(review),
        "suppressed": len(noise),
        "severity": severity_summary(alerts),
        "agents": agent_summary(alerts),
        "profile": profile,
    }


def severity_summary(alerts):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        level = int(nested(alert, ["rule", "level"], 0) or 0)
        if level >= 15:
            counts["critical"] += 1
        elif level >= 12:
            counts["high"] += 1
        elif level >= 7:
            counts["medium"] += 1
        else:
            counts["low"] += 1
    return counts


def agent_summary(alerts):
    active_agents = {
        nested(alert, ["agent", "name"], "")
        for alert in alerts
        if nested(alert, ["agent", "name"], "")
    }
    return {"active": len(active_agents), "disconnected": 0}


def context_query(alert):
    timestamp = alert.get("timestamp") or "now"
    agent_name = nested(alert, ["agent", "name"], "")
    return {
        "size": 20,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.name": agent_name}},
                    {"range": {"timestamp": {"gte": f"{timestamp}||-10m", "lte": f"{timestamp}||+10m"}}},
                ]
            }
        },
    }


class SocHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/health":
            try:
                health = request_indexer("/")
                rule_pack = load_rule_pack()
                self.send_json(
                    {
                        "mode": "live",
                        "indexer": INDEXER_URL,
                        "cluster": health.get("cluster_name", "wazuh"),
                        "triageRules": len(rule_pack["rules"]),
                        "triageRuleVersion": rule_pack["version"],
                    }
                )
            except Exception as error:
                self.send_json({"mode": "demo", "error": str(error)}, status=503)
            return

        if parsed.path == "/api/rules":
            rule_pack = load_rule_pack()
            self.send_json(
                {
                    "name": rule_pack["name"],
                    "version": rule_pack["version"],
                    "description": rule_pack["description"],
                    "path": rule_pack["path"],
                    "count": len(rule_pack["rules"]),
                    "error": rule_pack["error"],
                    "rules": [
                        {
                            "id": rule["id"],
                            "title": rule["title"],
                            "status": rule["status"],
                            "score": rule["score"],
                            "mitre": rule["mitre"],
                        }
                        for rule in rule_pack["rules"]
                    ],
                }
            )
            return

        if parsed.path == "/api/alerts":
            try:
                size = min(int(params.get("size", ["50"])[0]), 100)
                profile = params.get("profile", ["candidates"])[0]
                result = request_indexer("/wazuh-alerts-*/_search", alerts_query(params))
                hits = result.get("hits", {}).get("hits", [])
                alerts = [simplify_alert(hit) for hit in hits]
                visible_alerts, summary = apply_profile(alerts, profile, size)
                self.send_json({"mode": "live", "count": len(visible_alerts), "summary": summary, "alerts": visible_alerts})
            except Exception as error:
                self.send_json({"mode": "demo", "error": str(error), "alerts": []}, status=502)
            return

        if parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/context"):
            alert_id = urllib.parse.unquote(parsed.path.split("/")[3])
            index = params.get("index", [""])[0]
            try:
                alert_hit = request_indexer(f"/{urllib.parse.quote(index)}/_doc/{urllib.parse.quote(alert_id)}")
                alert = simplify_alert({"_id": alert_id, "_index": index, "_source": alert_hit.get("_source", {})})
                context_result = request_indexer("/wazuh-alerts-*/_search", context_query(alert))
                hits = context_result.get("hits", {}).get("hits", [])
                self.send_json({"mode": "live", "events": [simplify_alert(hit) for hit in hits]})
            except Exception as error:
                self.send_json({"mode": "demo", "error": str(error), "events": []}, status=502)
            return

        super().do_GET()


def main():
    port = int(os.getenv("PORT", "5174"))
    server = ThreadingHTTPServer(("127.0.0.1", port), SocHandler)
    print(f"AI SOC live dashboard serving http://127.0.0.1:{port}")
    print(f"Wazuh Indexer: {INDEXER_URL}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        print(f"Failed to start server: {error}", file=sys.stderr)
        sys.exit(1)
