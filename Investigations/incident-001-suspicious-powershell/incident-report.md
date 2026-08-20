# Incident Report: Suspicious PowerShell Execution

## Executive Summary

On July 14, 2026, Wazuh generated an alert for nested PowerShell execution on `WIN11-SOC-ENDPOINT`. The alert was based on Sysmon Event ID 1 and identified that PowerShell spawned another PowerShell instance with `-NoProfile` and `-ExecutionPolicy Bypass`.

The activity was intentionally generated for this SOC lab. No evidence of compromise was identified in the reviewed surrounding events.

## Alert Details

| Field | Value |
| --- | --- |
| SIEM | Wazuh |
| Endpoint | `WIN11-SOC-ENDPOINT` |
| Agent ID | `001` |
| Alert rule | `92027` |
| Rule description | `Powershell process spawned powershell instance` |
| Rule level | `4` |
| Source event | Sysmon Event ID `1` |
| MITRE ATT&CK | `T1059.001 - PowerShell` |
| Tactic | Execution |

## Command Line

```text
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'WAZUH-POWERSHELL-TEST-002'; whoami; hostname"
```

## Timeline

| Time | Source | Activity |
| --- | --- | --- |
| 2026-07-13 14:56:01 UTC | Sysmon | PowerShell process creation captured with `-ExecutionPolicy Bypass` |
| 2026-07-13 09:43:32 local | PowerShell Operational | Script block logging test captured |
| 2026-07-14 08:41:15 UTC | Sysmon via Wazuh | Nested PowerShell process creation captured |
| 2026-07-14 12:41:16 local | Wazuh | Alert `92027` fired |
| 2026-07-14 12:36-12:56 local | Wazuh | Surrounding documents reviewed |

## Investigation Findings

The alert matched a suspicious PowerShell execution pattern because one PowerShell process launched another PowerShell process. The command used `-NoProfile` and `-ExecutionPolicy Bypass`, which can be seen in both legitimate administrative work and attacker tradecraft.

The surrounding document review did not show clear follow-on malicious activity. Nearby events were primarily routine Windows service and background task events, including `svchost.exe`, `backgroundTaskHost.exe`, and Software Protection Platform service activity.

## MITRE ATT&CK Mapping

- `T1059.001 - Command and Scripting Interpreter: PowerShell`
- Tactic: Execution

## Detection Logic

Detection artifacts:

- `Detections/sigma/powershell_spawned_powershell.yml`
- `Detections/sigma/suspicious_powershell_executionpolicy_bypass.yml`
- `Detections/wazuh-dql/powershell_spawned_powershell.dql`

Wazuh DQL:

```text
agent.name: "WIN11-SOC-ENDPOINT" and rule.id: 92027
```

## Response Plan

For a production environment, an analyst should:

1. Validate whether the command was authorized.
2. Review parent and child process relationships.
3. Search for related PowerShell script block events.
4. Check for related downloads, file changes, account changes, persistence, or outbound network connections.
5. Escalate only if supporting malicious activity is found.

## Conclusion

This was a controlled lab-generated event. The lab successfully demonstrated endpoint telemetry collection, SIEM alerting, investigation workflow, MITRE mapping, detection logic creation, and AI-assisted incident reporting.

## Lessons Learned

- Sysmon Event ID 1 is highly useful for investigating command-line process execution.
- PowerShell Event ID 4104 adds valuable script content visibility.
- Wazuh can map endpoint alerts to MITRE ATT&CK techniques.
- AI summaries are useful for drafting, but the analyst must validate every conclusion against evidence.
