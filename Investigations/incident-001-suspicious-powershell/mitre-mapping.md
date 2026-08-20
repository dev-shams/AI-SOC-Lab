# MITRE ATT&CK Mapping

## T1059.001: Command and Scripting Interpreter: PowerShell

PowerShell was executed on the endpoint and captured by Sysmon Event ID 1, PowerShell Event ID 4104, and Wazuh alert rule `92027`.

Evidence:

- `powershell.exe` process creation
- Command-line argument: `-ExecutionPolicy Bypass`
- Script block logging event containing PowerShell command text
- Wazuh alert: `Powershell process spawned powershell instance`
- Wazuh MITRE mapping: `T1059.001`, tactic `Execution`
- Screenshot evidence: `Evidence/wazuh-alert-mitre-t1059-001-powershell.png`

Assessment:

This is a telemetry validation event, not a confirmed attack. The mapping is used because the observed behavior matches the PowerShell technique category, but the final incident conclusion should clearly state that the activity was lab-generated.

## Possible Future Mappings

These should only be added after generating supporting evidence:

- T1136: Create Account
- T1098: Account Manipulation
- T1071: Application Layer Protocol
- T1105: Ingress Tool Transfer
