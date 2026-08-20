# Timeline

| Time | Source | Event ID | Activity | Notes |
| --- | --- | ---: | --- | --- |
| 2026-07-13 14:56:01 UTC | Sysmon | 1 | PowerShell process created | Captured `powershell.exe` with `-NoProfile -ExecutionPolicy Bypass` |
| 2026-07-13 09:43:32 local | PowerShell Operational | 4104 | Script block logged | Captured `Write-Output "SOC-POWER-SHELL-LOGGING-TEST-12345"` |
| 2026-07-14 08:41:15 UTC | Sysmon via Wazuh | 1 | PowerShell spawned PowerShell | Captured nested PowerShell execution containing `WAZUH-POWERSHELL-TEST-002` |
| 2026-07-14 12:41:16 local | Wazuh alert | 92027 | Alert fired | `Powershell process spawned powershell instance`, level 4, MITRE `T1059.001` |
| 2026-07-14 12:36-12:56 local | Wazuh surrounding documents | Multiple | Context reviewed | Nearby events mostly show `svchost.exe`, `backgroundTaskHost.exe`, and Software Protection Platform activity |

## Notes

- Sysmon records `UtcTime`, while Event Viewer displays local time in the event list.
- The lab machine timezone and reporting timezone should be normalized before the final incident report.
- Wazuh dashboard timestamps are shown in local browser time. For this lab, local time is UTC+4.
- Reviewed surrounding documents did not show clear follow-on attacker behavior after the PowerShell test alert.
