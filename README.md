# AI-Powered SOC Investigation Lab

This project is a hands-on SOC lab that follows the full alert lifecycle:

1. Generate security events.
2. Collect telemetry into a SIEM.
3. Trigger alerts.
4. Investigate and build a timeline.
5. Map activity to MITRE ATT&CK.
6. Write detection logic.
7. Use an AI layer to draft investigation notes and response plans.
8. Publish the final incident report and lessons learned.

## Current Lab Status

- Endpoint VM: `WIN11-SOC-ENDPOINT`
- Host platform: UTM on Apple Silicon macOS
- SIEM: Local Wazuh stack running in Docker Desktop
- Wazuh endpoint agent: active on `WIN11-SOC-ENDPOINT`
- Endpoint telemetry:
  - Sysmon installed and writing to `Microsoft-Windows-Sysmon/Operational`
  - PowerShell Script Block Logging enabled
  - PowerShell Module Logging enabled
  - PowerShell Transcription enabled

## First Incident Scenario

Incident 001 validates that endpoint telemetry is working by capturing PowerShell execution with suspicious command-line options:

- Sysmon Event ID 1: PowerShell process creation
- PowerShell Event ID 4104: Script block logging
- Wazuh alert rule `92027`: PowerShell process spawned PowerShell instance
- MITRE ATT&CK: `T1059.001` PowerShell
- Evidence folder: `Investigations/incident-001-suspicious-powershell/Evidence/`

## Next Major Milestone

The project now has two tracks:

- `Investigations/`: hands-on SOC lab evidence and reporting.
- `soc-ai-platform/`: a live demo-mode AI SOC web app.

The next phase is productizing the AI SOC platform:

1. Run the free demo-mode web app locally.
2. Polish the dashboard workflow.
3. Deploy the static demo online.
4. Later, replace demo-mode AI with a backend LLM integration.
