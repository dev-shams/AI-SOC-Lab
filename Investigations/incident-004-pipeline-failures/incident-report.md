# Incident Report 004: Two Silent Detection Failures

**Status:** Closed — both root causes identified and fixed
**Analyst:** Shams
**Dates of activity:** 2026-08-22 to 2026-08-25
**Severity:** High — one caused total loss of endpoint visibility

---

## Executive Summary

Incidents 001 through 003 document attacks the pipeline caught. This one
documents two ways the pipeline was **wrong while appearing healthy**, found
during routine testing rather than by any alert.

1. **Total telemetry loss.** On two separate days, no events from
   `WIN11-SOC-ENDPOINT` reached the SIEM at all. The agent service reported
   `Running`, the manager listed the agent, and the console showed a green
   "Live Wazuh" indicator throughout. The only symptom was an expected alert
   not appearing — which is precisely the symptom nobody notices in
   production, because you do not know what *should* have fired.

2. **A false positive at the top of the queue.** Routine Windows automatic
   maintenance was scored 98/100 and ranked as the most urgent item needing
   investigation, for three days, while the detection it displaced was real.

Neither failure produced an error. Both were found only because a known
attack was run and the expected alert did not arrive.

---

## Part 1 — Silent telemetry loss

### Timeline

| Date | Mac IP | Agent configured for | Result |
| --- | --- | --- | --- |
| ~2026-07 | `192.168.1.165` | `192.168.1.165` | Working — incidents 001–003 collected |
| 2026-08-22 | `192.168.70.130` | `192.168.1.165` (stale) | Silent loss |
| 2026-08-24 | `192.168.1.141` | `192.168.70.130` (stale) | Silent loss |
| 2026-08-24 (after fix) | — | `192.168.64.1` | Working |

### How it presented

Running `Invoke-SocLabScenario.ps1 -Scenario EncodedPowerShell` produced no
alert. Everything downstream looked correct:

- `Get-Service Wazuh` → `Running`
- Sysmon locally recorded the event — **461** Event ID 1s in 20 minutes, 3
  containing `-EncodedCommand`
- The console displayed **"Live Wazuh"** with a healthy alert count
- Wazuh rule `92057` existed and its conditions matched the event exactly

Because alerts *were* visible in the console, the obvious conclusion — that
collection was broken — looked immediately disproved. Those alerts turned out
to be from `wazuh.manager` itself and from earlier in the day, not live
endpoint telemetry.

### Root cause

The Wazuh agent sends to a fixed address in `ossec.conf`:

```xml
<client><server><address>192.168.70.130</address></server></client>
```

That was the Mac's DHCP-assigned Wi-Fi address. When the router issued a new
lease — twice, across two different subnets — the agent kept sending to an
address that no longer existed. **A Wazuh agent does not report a dead manager
as an error state**; it retries silently, and `agent_control -l` showed
`Disconnected` only when specifically asked.

### Diagnosis method

Guesswork failed repeatedly here. What settled it was enabling full event
archiving on the manager:

```xml
<logall_json>yes</logall_json>
```

That records every event the manager receives, whether or not a rule fires,
which cleanly separates two questions that otherwise look identical:

- *Does the event arrive and fail to match a rule?*
- *Does the event never arrive?*

The answer was unambiguous:

```
events archived:                400
containing "EncodedCommand":      0
Sysmon channel events:            0
events from WIN11-SOC-ENDPOINT:   0   ← all 400 came from wazuh.manager itself
```

### Fix

Point the agent at the Mac's address on UTM's private VM network rather than
its Wi-Fi address:

```xml
<address>192.168.64.1</address>
```

`192.168.64.1` exists only between the host and the VM. It does not change when
the Mac joins a different network. The agent reconnected in 5 seconds and 797
events arrived immediately.

### Verification

After the fix, the same scenario produced the expected result end to end:

```
archived event   decoder: windows_eventchannel   rule fired: 92057
indexed alert    2026-08-24T07:25:40Z  rule 92057  level 12  T1059.001
console          1 candidate  ·  policy SOC-PS-002  ·  score 98
```

The full account-lifecycle scenario also landed — all 7 events, `4720` through
`4726`, matching Incident 003.

---

## Part 2 — False positive at the top of the queue

### What fired

Four alerts on Wazuh rule `91823`, *"Powershell script used Invoke-command
cmdlet to execute code on remote computer"*, level 14, scored **98/100** by
triage policy `SOC-PS-003` and ranked first in "Needs investigation".

They arrived at 18:04 UTC with no user present.

### Investigation

The surrounding events identified the activity immediately:

| Time (UTC) | Event |
| --- | --- |
| 18:02:39 | `cmd.exe /d /c hpatchmonTask.cmd` — launched by `svchost.exe` (scheduled task) |
| 18:04:11 | ESENT database engine starting, replaying logs, attaching a database |
| 18:04:22 | ⚠ rule `91823` |
| 18:04:43 | ⚠ rule `91823` |
| 18:06:07 | `sdbinst.exe -m -bg` — application-compatibility shim installer |

ESENT recovery plus `sdbinst.exe` is **Windows Automatic Maintenance** — the
servicing work Windows performs when a machine is idle. The VM had been left
running overnight.

### Why it matched

The script block that triggered the rule is a module **defining** proxy
functions:

```powershell
function Test-Caller {
    ...
    throw 'Invoke-Expression cannot be used in a script'
}

function Invoke-Expression {
    [CmdletBinding(HelpUri='https://go.microsoft.com/fwlink/?LinkID=2097030')]
    param([Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)][string]${Command})
```

`Invoke-Expression` and `Invoke-Command` appear here as **names being
declared** and inside a **guard message**. Nothing was executed and nothing was
downloaded.

There is an irony worth recording: this module exists specifically to *block*
`Invoke-Expression` inside scripts. A defensive control was being reported as
an attack.

Both detection layers made the same mistake:

- **Wazuh rule `91823`** matches `Invoke-Command` anywhere in script-block text.
- **Triage rule `SOC-PS-003`** listed `invoke-expression` in its `any_text`,
  so a declaration matched as readily as a call.

This is the classic failure of **matching on a string rather than on
behaviour**.

### Fix

`SOC-PS-003` was conflating two signals of very different strength: *fetching*
content from the network, and *executing* a string. They were split.

**`SOC-PS-003` — download cradle** (candidate, 98). Download primitives only:

```
downloadstring · downloadfile · downloaddata · net.webclient
invoke-webrequest · invoke-restmethod · start-bitstransfer
```

**`SOC-PS-005` — in-memory execution keyword** (review, 60). `invoke-expression`
and ` iex ` now sit here. Executing a string is a far weaker signal than
fetching one, and on its own it is dominated by legitimate module code.

Both carry exclusions that identify a definition rather than a call:

```
function invoke-expression · function invoke-command
cmdletbinding(helpuri     · cannot be used in a script
```

`cmdletbinding(helpuri` is the most general of these: Microsoft-generated proxy
function definitions carry a `HelpUri` attribute, which an invocation never does.

### Verification

All 140 alerts in the snapshot were re-triaged under both rule packs:

```
alerts re-triaged: 140
verdicts changed:    4   ← all four are the false positives

  wazuh 91823   BEFORE: candidate  98  SOC-PS-003
                AFTER : review     65  (fallback)

candidates: 20 → 16      no true positive lost
```

The alert still appears under "Worth a look" rather than being suppressed. That
is deliberate: Wazuh rated it level 14, and hiding it entirely would be the
opposite mistake. The change is one of **priority**, not visibility.

Six regression tests in
[`test_server.py`](../../soc-ai-platform/test_server.py) lock the behaviour in,
using the real script-block text captured on 2026-08-24. They assert that a
genuine cradle (`IEX (New-Object Net.WebClient).DownloadString(...)`) and
`Invoke-WebRequest` both still score 98.

---

## MITRE ATT&CK Mapping

Neither finding maps to an adversary technique — no adversary was involved.
They map to detection-capability gaps, which is the point:

| Finding | Category | Effect |
| --- | --- | --- |
| Silent telemetry loss | Visibility gap | 100% loss of endpoint coverage; every technique undetectable |
| False positive | Precision gap | Analyst attention drawn to benign activity; real alerts displaced |

The first is the more serious. During both outages the endpoint was
**completely unmonitored**, so any of T1059.001, T1136.001 or T1098 —
techniques this lab demonstrably detects — would have passed unseen.

---

## Lessons Learned

1. **A green status indicator is not evidence of collection.** Every component
   reported healthy during total telemetry loss. "Agent connected" means a
   keepalive arrived, not that events are flowing.
2. **Pin agents to stable addresses.** A DHCP lease is not a configuration
   value. The host-only network address existed the whole time and would have
   prevented both outages.
3. **Full event archiving is the tool for "why didn't this alert?"** It is the
   only way to distinguish "never arrived" from "arrived and matched nothing".
   It is off by default and worth turning on temporarily when a detection is
   under investigation.
4. **Validate detections against the absence of alerts, not just their
   presence.** Both failures were found by running a known attack and noticing
   nothing happened. A pipeline with no such test will not notice it has gone
   blind.
5. **Keyword matching is not behavioural detection.** A rule matching
   `Invoke-Expression` cannot distinguish a call from a declaration. Where a
   keyword is unavoidable, pair it with a second condition — here, evidence of
   an actual download.
6. **Test the fix against every alert, not just the failing one.** Re-triaging
   all 140 snapshot alerts proved the change corrected 4 verdicts and broke
   none. Spot-checking the one broken case would not have.

---

## Evidence

- Agent configuration before and after, with `TcpTestSucceeded` confirmations — session transcript
- Manager archive counts proving zero endpoint events — `/var/ossec/logs/archives/archives.json`
- Archived event showing `decoder: windows_eventchannel` and `rule fired: 92057` after the fix
- False-positive script-block text — preserved verbatim in the regression tests
- Before/after triage comparison across 140 alerts — reproducible with the committed rule packs

### Reproducing the triage comparison

```bash
git show 9724247:soc-ai-platform/rules/triage-rules.json > /tmp/triage-before.json
# then re-triage soc-ai-platform/sample-data/snapshot.json under each pack
```
