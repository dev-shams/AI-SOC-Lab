# Incident Report 002: Base64-Encoded PowerShell Execution

**Status:** Closed — authorized lab simulation
**Analyst:** Shams
**Date of activity:** 2026-07-23
**Severity:** High (Wazuh level 12)

---

## Executive Summary

On 2026-07-23 at 07:10:13 UTC, Wazuh raised a level 12 alert on
`WIN11-SOC-ENDPOINT` for a PowerShell process that executed a base64-encoded
command. A parent `powershell.exe` spawned a child `powershell.exe` with the
`-NoProfile -EncodedCommand` switches, hiding the actual command from anyone
reading the process list or a command-line log field.

Decoding the payload showed it was benign: it printed a marker string and ran
`whoami` and `hostname`. The activity was generated deliberately by
`Invoke-SocLabScenario.ps1 -Scenario EncodedPowerShell` as part of detection
validation. No follow-on activity was observed.

The value of this case is not the payload. It is that the detection pipeline
correctly caught an execution technique whose entire purpose is to be
unreadable, and that the console decoded it automatically so the analyst did
not have to.

---

## Alert Details

| Field | Value |
| --- | --- |
| SIEM | Wazuh (local single-node) |
| Endpoint | `WIN11-SOC-ENDPOINT` |
| Agent ID | `001` |
| Wazuh rule | `92057` |
| Rule description | Powershell.exe spawned a powershell process which executed a base64 encoded command |
| Rule level | `12` (High) |
| Source channel | `Microsoft-Windows-Sysmon/Operational` |
| Windows Event ID | `1` (Process Create) |
| Alert timestamp | `2026-07-23T07:10:13.264Z` |
| Sysmon systemTime | `2026-07-23T07:10:11.786Z` |
| User | `WIN11-SOC-ENDPO\Shams` |
| Working directory | `C:\Users\Shams\` |
| Process ID / Parent PID | `2780` / `5700` |
| Triage policy match | `SOC-PS-002` — PowerShell encoded command (score 98, candidate) |

## Observed Command Line

```text
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMATwBDAC0ATABBAEIALQBFAE4AQwBPAEQARQBEAC0AMAAwADEAJwA7ACAAdwBoAG8AYQBtAGkAOwAgAGgAbwBzAHQAbgBhAG0AZQA=
```

Parent process:

```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

## Decoded Payload

The `-EncodedCommand` argument is UTF-16LE base64. Decoded:

```powershell
Write-Output 'SOC-LAB-ENCODED-001'; whoami; hostname
```

Benign: a marker string, the current user context, and the hostname. In a real
intrusion this position in the command is where a download cradle, a reverse
shell, or an in-memory loader would sit.

The AI SOC console decodes this server-side before analysis, so both the
analyst and the model reason about the real command rather than the base64
blob. See `decoded_powershell()` in
[`soc-ai-platform/templates.py`](../../soc-ai-platform/templates.py).

---

## Investigation

**Scope of surrounding activity.** Alerts within a ±2 minute window on the same
endpoint were reviewed. Only two alerts exist in that window:

| Time (UTC) | Rule | Description |
| --- | --- | --- |
| 07:10:13 | `92057` | The encoded PowerShell alert itself |
| ~07:11 | `60642` | Software protection service scheduled successfully (routine Windows) |

**What was checked and ruled out.**

- No file downloads or `Invoke-WebRequest` / `DownloadString` activity.
- No new accounts or group membership changes in the window.
- No scheduled task creation or Run key modification.
- No outbound network connection alerts.
- No child processes beyond the PowerShell instance itself.

**Why the parent-child relationship matters.** A `powershell.exe` spawning
another `powershell.exe` is unusual in normal interactive use. Combined with
`-NoProfile` (skips the user profile, avoiding both slowdown and any profile
logging) and `-EncodedCommand`, the three together form a recognisable pattern:
the caller wanted a clean, fast, unreadable execution. Each switch is
individually legitimate. The combination is the signal.

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Evidence | Confidence |
| --- | --- | --- | --- |
| `T1059.001` — Command and Scripting Interpreter: PowerShell | Execution | `powershell.exe` process creation with `-Command` payload, Sysmon Event ID 1 | High |
| `T1027` — Obfuscated Files or Information | Defense Evasion | `-EncodedCommand` with a base64 UTF-16LE payload | High |

Wazuh's built-in mapping for rule `92057` only asserts `T1059.001`. The
`T1027` mapping is added by triage policy `SOC-PS-002`, because the encoding
is a distinct defence-evasion behaviour and not part of the execution technique
itself. The console merges both mappings for display.

---

## Detection Logic

Sigma rule: [`Detections/sigma/powershell_encoded_command.yml`](../../Detections/sigma/powershell_encoded_command.yml)

Wazuh hunting query:

```text
data.win.system.eventID: 1 and data.win.eventdata.image: "*powershell.exe" and (data.win.eventdata.commandLine: "*-EncodedCommand*" or data.win.eventdata.commandLine: "*-enc *")
```

**Deliberate design choice:** the rule matches on `-EncodedCommand` / `-enc`,
not on the `SOC-LAB-ENCODED-001` marker string. A rule keyed to the lab marker
would pass this test and catch nothing real. This is also why the triage pack
scores lab-marker rules below behavioural rules.

**Known false positives.** Encoded PowerShell is common in legitimate tooling —
software deployment systems, configuration management, and installers encode
commands routinely to avoid quoting problems. This rule is a starting point for
investigation, not grounds for automated containment. Tune by excluding known
parent processes (deployment agents) rather than by weakening the match.

---

## Response Actions Taken

As authorized lab activity, no containment was required. The response path that
*would* apply in production:

1. **Do now:** decode the payload and read it. Everything else depends on what
   it says.
2. **Do now:** confirm the parent process chain — what launched the first
   PowerShell?
3. **Do if confirmed malicious:** isolate the endpoint, capture memory before
   reboot, preserve the PowerShell transcript at
   `C:\SOC-Lab\PowerShell-Transcripts`.
4. **Follow up:** hunt for the same encoded string or parent chain across all
   endpoints.

---

## Lessons Learned

1. **Decoding must be automatic.** An analyst who has to manually base64-decode
   every alert will eventually skip one. Building the decode into the console
   removed that failure mode.
2. **Level 12 was the right severity.** Wazuh rated this higher than the
   plain PowerShell alert in Incident 001 (level 4), which correctly reflects
   that obfuscation raises suspicion even when the payload is unknown.
3. **The alert was genuinely isolated.** Confirming *absence* of follow-on
   activity took as much work as confirming the alert itself, and it is what
   justified closing the case rather than escalating.

---

## Evidence

- [`Evidence/wazuh-alert-92057-encoded-powershell.json`](Evidence/wazuh-alert-92057-encoded-powershell.json) — raw Wazuh alert document
- [`Evidence/wazuh-alert-92057-encoded-powershell-normalized.json`](Evidence/wazuh-alert-92057-encoded-powershell-normalized.json) — normalized view with triage verdict
