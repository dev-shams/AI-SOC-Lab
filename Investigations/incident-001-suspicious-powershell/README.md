# Incident 001: Suspicious PowerShell Telemetry Validation

## Summary

This incident validates that the Windows endpoint can generate, forward, and alert on investigation-quality telemetry for PowerShell activity. The activity is benign and lab-generated, but it uses command-line patterns commonly reviewed by SOC analysts, including `-NoProfile`, `-ExecutionPolicy Bypass`, and nested PowerShell execution.

## Environment

- Endpoint: `WIN11-SOC-ENDPOINT`
- User: `WIN11-SOC-ENDPO\Shams`
- Telemetry sources:
  - Sysmon Operational log
  - PowerShell Operational log
- SIEM:
  - Wazuh local Docker stack
  - Wazuh Windows agent `001`

## Observed Activity

The endpoint captured PowerShell execution through Sysmon Event ID 1. The command line included:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "whoami; hostname; Get-Date"
```

After Wazuh collection was configured for Sysmon and PowerShell Operational channels, a fresh controlled test generated a Wazuh alert:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'WAZUH-POWERSHELL-TEST-002'; whoami; hostname"
```

Wazuh alert details:

- Rule description: `Powershell process spawned powershell instance`
- Rule ID: `92027`
- Rule level: `4`
- Event channel: `Microsoft-Windows-Sysmon/Operational`
- Windows event ID: `1`
- MITRE technique: `T1059.001` PowerShell
- MITRE tactic: Execution

The endpoint also captured PowerShell Script Block Logging through Event ID 4104 for a controlled test command:

```powershell
Write-Output "SOC-POWER-SHELL-LOGGING-TEST-12345"
```

## Evidence

- `Evidence/sysmon-event-id-1-powershell-executionpolicy-bypass.png`
- `Evidence/powershell-event-id-4104-scriptblock-logging-test.png`
- `Evidence/powershell-event-id-4104-scriptblock-logging-test.evtx`
- `Evidence/sysmon-event-id-1-powershell-executionpolicy-bypass.xml`
- `Evidence/wazuh-alert-powershell-process-details-1.png`
- `Evidence/wazuh-alert-powershell-process-details-2.png`
- `Evidence/wazuh-alert-powershell-rule-mitre.png`
- `Evidence/wazuh-surrounding-documents-powershell-alert.png`
- `Evidence/wazuh-alert-mitre-t1059-001-powershell.png`

The PowerShell 4104 event was exported as EVTX because the shared WebDAV folder intermittently locked direct XML writes from Notepad.

Raw XML export still needs to be added for:

- `Evidence/powershell-event-id-4104-scriptblock-logging-test.xml`

## Analyst Assessment

This activity is not malicious in this lab context. It confirms that the endpoint can record process creation and script block telemetry, forward Sysmon events into Wazuh, and produce a SIEM alert that an analyst can investigate.

The use of `-ExecutionPolicy Bypass` is important because attackers and administrators can use it to run PowerShell commands while bypassing local execution policy controls. In a real SOC, this command-line pattern should be reviewed with surrounding context such as user, parent process, endpoint role, source alert, and related network or file activity.

Surrounding Wazuh documents showed mostly routine Windows service activity, including `svchost.exe`, `backgroundTaskHost.exe`, and Software Protection Platform events. No follow-on malware download, account creation, persistence, or outbound connection evidence was observed in the reviewed window.

## Status

SIEM alert validation and MITRE mapping complete. Detection logic has been drafted in:

- `Detections/sigma/powershell_spawned_powershell.yml`
- `Detections/sigma/suspicious_powershell_executionpolicy_bypass.yml`
- `Detections/wazuh-dql/powershell_spawned_powershell.dql`

Next step: prepare the incident report and AI-assisted response summary.
