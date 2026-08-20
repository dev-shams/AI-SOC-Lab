#!/usr/bin/env python3
"""Deterministic, evidence-bound artifact templates.

These are the fallback the console uses when the Claude layer is unavailable
(no API key, SDK missing, request failed, or the model declined). They only
interpolate fields that are actually present in the normalized alert, so the
output is always traceable back to the Wazuh document.
"""
import base64
import re

ENCODED_COMMAND = re.compile(r"-(?:EncodedCommand|enc)\s+[\"']?([A-Za-z0-9+/=]{8,})", re.I)

TECHNIQUE_NAMES = {
    "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery",
    "T1053.005": "Scheduled Task",
    "T1059.001": "PowerShell",
    "T1060": "Registry Run Keys / Startup Folder",
    "T1082": "System Information Discovery",
    "T1087.001": "Local Account Discovery",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1136.001": "Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
}


def command_line(alert):
    return (
        alert.get("process", {}).get("commandLine")
        or alert.get("event", {}).get("message")
        or "No command line available"
    )


def endpoint(alert):
    return alert.get("agent", {}).get("name") or "Unknown endpoint"


def decoded_powershell(alert):
    """Decode a base64 -EncodedCommand payload, or return an empty string."""
    match = ENCODED_COMMAND.search(command_line(alert))
    if not match:
        return ""
    payload = match.group(1)
    payload += "=" * (-len(payload) % 4)
    try:
        return base64.b64decode(payload).decode("utf-16-le").replace("\0", "").strip()
    except (ValueError, UnicodeDecodeError):
        return ""


def mitre_ids(alert):
    """Wazuh's own mapping plus any mapping asserted by the triage policy."""
    wazuh_id = alert.get("rule", {}).get("mitreId", "")
    policy_ids = alert.get("triage", {}).get("mitre", []) or []
    ordered = ([wazuh_id] if wazuh_id else []) + list(policy_ids)
    seen = []
    for item in ordered:
        if item and item not in seen:
            seen.append(item)
    return seen


def mitre_labels(alert):
    labels = []
    for technique_id in mitre_ids(alert):
        name = TECHNIQUE_NAMES.get(technique_id) or alert.get("rule", {}).get(
            "mitreTechnique", ""
        )
        labels.append(f"{technique_id} - {name}" if name else technique_id)
    return labels or ["Unmapped"]


def detection_profile(alert):
    configured = alert.get("triage", {}).get("detection") or {}
    if configured:
        return configured

    command = command_line(alert).lower()
    if "-encodedcommand" in command or " -enc " in command:
        return {
            "title": "PowerShell Encoded Command",
            "image_endswith": "\\powershell.exe",
            "command_line_any": ["-EncodedCommand", "-enc "],
            "level": "high",
            "false_positives": ["Legitimate encoded administration scripts"],
        }

    image = alert.get("process", {}).get("image") or "process.exe"
    return {
        "title": alert.get("rule", {}).get("description") or "Suspicious Process Creation",
        "image_endswith": "\\" + image.split("\\")[-1],
        "command_line_any": [],
        "level": "medium",
        "false_positives": ["Authorized administrator activity"],
    }


def dql_for(alert):
    profile = detection_profile(alert)
    event_id = alert.get("event", {}).get("eventId") or "1"
    image_name = (profile.get("image_endswith") or "process.exe").split("\\")[-1]
    terms = [
        f'data.win.eventdata.commandLine: "*{str(term).strip()}*"'
        for term in profile.get("command_line_any", [])
    ]
    clauses = [
        f"data.win.system.eventID: {event_id}",
        f'data.win.eventdata.image: "*{image_name}"',
    ]
    if len(terms) > 1:
        clauses.append("(" + " or ".join(terms) + ")")
    elif terms:
        clauses.append(terms[0])
    return " and ".join(clauses)


def sigma_for(alert):
    profile = detection_profile(alert)
    image = (profile.get("image_endswith") or "\\process.exe").replace("'", "''")
    terms = profile.get("command_line_any", [])
    condition = "selection_image and selection_command" if terms else "selection_image"
    command_block = ""
    if terms:
        entries = "\n".join(f"      - '{str(term).replace(chr(39), chr(39) * 2)}'" for term in terms)
        command_block = f"  selection_command:\n    CommandLine|contains:\n{entries}\n"
    false_positives = "\n".join(
        f"  - {item}" for item in profile.get("false_positives", ["Authorized activity"])
    )
    tags = "\n".join(f"  - attack.{item.lower()}" for item in mitre_ids(alert)) or "  - attack.t1059.001"
    title = profile.get("title") or "Suspicious Process Creation"

    return f"""title: {title}
status: experimental
description: Detects {title.lower()}.
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '{image}'
{command_block}  condition: {condition}
fields:
  - Image
  - ParentImage
  - CommandLine
  - User
falsepositives:
{false_positives}
level: {profile.get("level", "medium")}
tags:
  - attack.execution
{tags}"""


def _context_note(context_events):
    if context_events:
        return f"Loaded {len(context_events)} surrounding events from Wazuh for the same endpoint."
    return "Surrounding events have not been loaded yet."


def render(alert, context_events, task, question=""):
    """Render one deterministic artifact for the given task."""
    rule = alert.get("rule", {})
    event = alert.get("event", {})
    triage = alert.get("triage", {})
    context_note = _context_note(context_events)
    banner = (
        "_Generated by the deterministic template engine. The Claude layer is "
        "unavailable, so this is field interpolation, not model analysis._"
    )

    if task == "timeline":
        body = f"""## Timeline

| Time | Source | Event | Interpretation |
| --- | --- | --- | --- |
| {alert.get("timestamp", "Unknown")} | {event.get("channel", "Unknown")} | Event ID {event.get("eventId", "unknown")} | {rule.get("description", "No description")} |

**Command or event text**

```text
{command_line(alert)}
```

{context_note}"""

    elif task == "mitre":
        mappings = "\n".join(f"- {label}" for label in mitre_labels(alert))
        body = f"""## MITRE ATT&CK Mapping

{mappings}

**Tactic:** {rule.get("mitreTactic") or "Not mapped by Wazuh"}

These mappings combine Wazuh rule metadata with the matched triage policy.
MITRE mapping describes behaviour; it does not prove malicious intent."""

    elif task == "response":
        body = f"""## Response Plan

1. Confirm whether the observed activity was authorized.
2. Review parent and child process relationships around the alert.
3. Search Sysmon and PowerShell telemetry for the same user and host.
4. Look for downloads, account changes, persistence, credential access, or outbound connections.
5. Escalate only if supporting suspicious evidence is found.

{context_note}"""

    elif task == "detection":
        body = f"""## Detection Logic

**Wazuh DQL**

```text
{dql_for(alert)}
```

**Sigma draft**

```yaml
{sigma_for(alert)}
```"""

    elif task == "chat":
        body = f"""## Evidence for: {question or "your question"}

The template engine cannot answer free-form questions. Here are the alert facts:

- **Rule:** {rule.get("id", "unknown")} - {rule.get("description", "No description")} (level {rule.get("level", "unknown")})
- **Endpoint:** {endpoint(alert)}
- **Source:** {event.get("channel", "unknown")} Event ID {event.get("eventId", "unknown")}
- **Triage:** {triage.get("status", "review")} - {triage.get("reason", "No reason")}

```text
{command_line(alert)}
```

Set `ANTHROPIC_API_KEY` to enable model-written analysis."""

    else:
        decoded = decoded_powershell(alert)
        decoded_block = f"\n\n**Decoded payload**\n\n```powershell\n{decoded}\n```" if decoded else ""
        body = f"""## Executive Summary

Wazuh generated an alert on **{endpoint(alert)}**. It matched rule `{rule.get("id", "unknown")}`,
"{rule.get("description", "No description")}", at level {rule.get("level", "unknown")}.

The source event is {event.get("channel", "unknown channel")} Event ID {event.get("eventId", "unknown")}.

- **Triage status:** {triage.get("status", "review")}
- **Triage reason:** {triage.get("reason", "No triage reason available")}
- **MITRE:** {", ".join(mitre_labels(alert))}

```text
{command_line(alert)}
```{decoded_block}

{context_note}"""

    return f"{body}\n\n---\n\n{banner}"


def report_for(alert, context_events=None):
    """Full markdown incident report, used by the Report view and Copy Report."""
    rule = alert.get("rule", {})
    event = alert.get("event", {})
    triage = alert.get("triage", {})
    decoded = decoded_powershell(alert)
    decoded_section = (
        f"\n## Decoded PowerShell Payload\n\n```powershell\n{decoded}\n```\n" if decoded else ""
    )

    return f"""# Incident Report: {rule.get("description", "Wazuh Alert")}

## Summary

Wazuh generated an alert on `{endpoint(alert)}` matching rule `{rule.get("id", "unknown")}`
at level {rule.get("level", "unknown")}.

## Alert Details

| Field | Value |
| --- | --- |
| Triage | {triage.get("status", "review")} - {triage.get("reason", "No reason")} |
| Policy rule | {triage.get("policyRule", "Default triage policy")} |
| Endpoint | `{endpoint(alert)}` |
| Wazuh rule | `{rule.get("id", "unknown")}` |
| Description | {rule.get("description", "No description")} |
| Level | {rule.get("level", "unknown")} |
| Source | {event.get("channel", "unknown")} |
| Event ID | {event.get("eventId", "unknown")} |
| MITRE | {", ".join(mitre_labels(alert))} |
| Tactic | {rule.get("mitreTactic") or "Not mapped"} |

## Command Or Event Text

```text
{command_line(alert)}
```
{decoded_section}
## Detection Logic

```text
{dql_for(alert)}
```

```yaml
{sigma_for(alert)}
```

## Context

{_context_note(context_events)}

## Analyst Validation

Validate every conclusion against the Wazuh alert document and endpoint evidence
before publishing this report.
"""
