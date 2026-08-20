# Incident 001 Case Brief: Suspicious PowerShell

## Purpose

Provide structured incident facts to an LLM so it can draft an investigation summary and response plan. The LLM output must be reviewed by the analyst before publication.

## Confirmed Environment

- Endpoint: `WIN11-SOC-ENDPOINT`
- Agent ID: `001`
- Endpoint IP in Wazuh: `192.168.64.3`
- User observed in event data: `WIN11-SOC-ENDPO\Shams`
- SIEM: Wazuh local Docker stack
- Telemetry sources:
  - Sysmon Operational log
  - PowerShell Operational log
  - Wazuh alerts

## Confirmed Alert

- Alert source: Wazuh
- Rule ID: `92027`
- Rule description: `Powershell process spawned powershell instance`
- Rule level: `4`
- Rule groups: `sysmon`, `sysmon_eid1_detections`, `windows`
- Timestamp: `Jul 14, 2026 @ 12:41:16.550` local browser time
- Windows event ID: `1`
- Windows channel: `Microsoft-Windows-Sysmon/Operational`
- MITRE ATT&CK ID: `T1059.001`
- MITRE tactic: `Execution`
- MITRE technique: `PowerShell`

## Command Line Evidence

```text
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'WAZUH-POWERSHELL-TEST-002'; whoami; hostname"
```

## Related Local Telemetry

- Sysmon Event ID 1 captured PowerShell process creation with suspicious command-line options.
- PowerShell Event ID 4104 captured script block logging during earlier telemetry validation.
- PowerShell transcription was configured to write to `C:\SOC-Lab\PowerShell-Transcripts`.

## Surrounding Context

Surrounding Wazuh documents showed mostly routine Windows service and background task activity:

- `svchost.exe`
- `backgroundTaskHost.exe`
- Software Protection Platform service events

No clear follow-on malware download, new admin account, persistence, or outbound command-and-control activity was observed in the reviewed surrounding-document window.

## Evidence Files

- `Investigations/incident-001-suspicious-powershell/Evidence/sysmon-event-id-1-powershell-executionpolicy-bypass.png`
- `Investigations/incident-001-suspicious-powershell/Evidence/sysmon-event-id-1-powershell-executionpolicy-bypass.xml`
- `Investigations/incident-001-suspicious-powershell/Evidence/powershell-event-id-4104-scriptblock-logging-test.png`
- `Investigations/incident-001-suspicious-powershell/Evidence/powershell-event-id-4104-scriptblock-logging-test.evtx`
- `Investigations/incident-001-suspicious-powershell/Evidence/wazuh-alert-powershell-process-details-1.png`
- `Investigations/incident-001-suspicious-powershell/Evidence/wazuh-alert-powershell-process-details-2.png`
- `Investigations/incident-001-suspicious-powershell/Evidence/wazuh-alert-mitre-t1059-001-powershell.png`
- `Investigations/incident-001-suspicious-powershell/Evidence/wazuh-surrounding-documents-powershell-alert.png`

## Analyst Guidance For LLM

- Do not claim compromise.
- Treat the activity as lab-generated telemetry validation.
- Explain why the behavior is suspicious in real environments.
- Separate confirmed facts from hypotheses.
- Include response actions appropriate for a real SOC, but mark them as recommended validation steps.
