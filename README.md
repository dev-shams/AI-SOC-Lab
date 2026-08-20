# AI-Powered SOC Investigation Lab

A self-contained security operations lab that runs the full alert lifecycle:
generate attacker-style telemetry on a Windows endpoint, collect it in Wazuh,
triage it, investigate with an LLM-backed analyst assistant, map it to MITRE
ATT&CK, write the detection rule, and publish the incident report.

Built to cover four roles in one project — SOC analyst (investigation),
detection engineer (rule writing), incident responder (documented response),
and threat hunter (proactive searching) — with an AI layer on top.

---

## Architecture

```
Windows 11 ARM VM (UTM)                 macOS host
┌─────────────────────────┐            ┌──────────────────────────────────┐
│ WIN11-SOC-ENDPOINT      │            │ Docker Desktop                   │
│                         │            │  ├── wazuh.manager   (rules)     │
│  Sysmon ────────────┐   │  agent     │  ├── wazuh.indexer   (storage)   │
│  PowerShell logging ┼───┼──1514/15──▶│  └── wazuh.dashboard (Wazuh UI)  │
│  Wazuh agent 001    ┘   │            │                                  │
│                         │            │ AI SOC Console (:5174)           │
│  Invoke-SocLabScenario  │            │  ├── triage policy pack          │
│  .ps1 (6 scenarios)     │            │  ├── Claude investigation layer  │
└─────────────────────────┘            │  └── Sigma / DQL generation      │
                                       └──────────────────────────────────┘
```

Detection and AI are deliberately separate concerns:

| Layer | Job | Where |
| --- | --- | --- |
| Wazuh + Sysmon | Detect activity, raise alerts | `wazuh-docker/` |
| Triage policy pack | Rank alerts, suppress lab noise | `soc-ai-platform/rules/triage-rules.json` |
| Claude assistant | Investigate the selected evidence | `soc-ai-platform/ai.py` |

The AI is **not** the detection engine. It never decides what fires; it reads
what already fired and helps the analyst reason about it. Feeding thousands of
detection rules into a prompt would be the wrong architecture — Wazuh already
ships 3,000+ rules and applies them before the console ever sees an alert.

---

## Repository layout

```
Investigations/     Incident writeups, timelines, MITRE mappings, evidence
Detections/         Sigma rules and Wazuh DQL hunting queries
Simulations/        Self-cleaning Windows attack scenario runner
AI-Layer/           Analyst prompt, case briefs, model output
soc-ai-platform/    The AI SOC console (backend + dashboard)
scripts/            Lab lifecycle, snapshot export, rule validation
```

`wazuh-docker/` is **not committed**. It is an upstream clone, and generating
the indexer certificates writes real private keys into it. Rebuild it with
`./scripts/setup-wazuh.sh`.

---

## Quick start

**Prerequisites:** Docker Desktop, Python 3.10+, and (for telemetry) a Windows
VM running Sysmon and the Wazuh agent.

```bash
git clone <your-repo-url> "AI SOC Lab" && cd "AI SOC Lab"
./scripts/setup-wazuh.sh
```

Install the console's optional AI dependency:

```bash
python3 -m venv soc-ai-platform/.venv && soc-ai-platform/.venv/bin/pip install -r soc-ai-platform/requirements.txt
```

Configure credentials:

```bash
cp .env.example .env
```

Then start everything:

```bash
./scripts/start-lab.sh
```

- Wazuh dashboard: `https://localhost`
- AI SOC console: `http://127.0.0.1:5174`

Stop with `./scripts/stop-lab.sh` (preserves data volumes).

---

## The AI layer

The investigation assistant runs on the Claude API. The system prompt is
composed from [`AI-Layer/prompts/investigation-summary-prompt.md`](AI-Layer/prompts/investigation-summary-prompt.md),
so the analyst-authored rules — separate fact from hypothesis, name missing
evidence, never assert malice the logs do not support — are what actually
govern the model.

Each request sends only the normalized Wazuh alert plus its surrounding events.
Base64 `-EncodedCommand` payloads are decoded server-side first, so the model
reasons about the real command rather than an opaque blob.

Five task types, plus free-form questions:

| Task | Produces |
| --- | --- |
| Summary | Shift-handover summary with a close/investigate/escalate call |
| Timeline | Chronological table, with telemetry gaps marked |
| MITRE | Technique mapping with the supporting evidence field per technique |
| Response | Containment plan tagged Do Now / Do If Confirmed / Follow Up |
| Detection | Complete Sigma rule and equivalent Wazuh DQL |

**Cost.** Roughly a cent or two per investigation. Token counts and the exact
dollar cost of every request are shown under each response, so nothing is
hidden. Set the key in `.env`:

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

**Without a key the console still works.** It falls back to a deterministic
template engine (`templates.py`) and labels itself "Template mode" in the
sidebar so the output is never mistaken for model analysis. This also covers
two other cases: a failed API request, and a safety refusal — the evidence
contains genuine attacker-style command lines, so `stop_reason: "refusal"` is
handled explicitly rather than surfacing as an empty panel.

---

## Generating telemetry

[`Simulations/Invoke-SocLabScenario.ps1`](Simulations/Invoke-SocLabScenario.ps1)
runs six safe scenarios from an Administrator PowerShell session in the VM. Each
one cleans up after itself — tasks unregistered, Run values removed, accounts
deleted.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
Z:\Simulations\Invoke-SocLabScenario.ps1 -Scenario EncodedPowerShell
```

| Scenario | Behaviour | ATT&CK |
| --- | --- | --- |
| `EncodedPowerShell` | Base64 `-EncodedCommand` execution | T1059.001, T1027 |
| `DiscoveryBurst` | Rapid local host and account enumeration | T1033, T1082, T1087.001 |
| `ScheduledTask` | Creates then removes a scheduled task | T1053.005 |
| `RunKey` | Writes then removes a `Run` key value | T1547.001 |
| `Certutil` | LOLBin encode of a local marker file | T1140 |
| `TemporaryAdmin` | Creates an account, grants admin, reverts | T1136.001, T1098 |

`-Scenario All` runs every one.

---

## Incidents

| # | Case | Behaviour | ATT&CK | Severity |
| --- | --- | --- | --- | --- |
| [001](Investigations/incident-001-suspicious-powershell/incident-report.md) | Suspicious PowerShell | Nested PowerShell with `-ExecutionPolicy Bypass` | T1059.001 | Level 4 |
| [002](Investigations/incident-002-encoded-powershell/incident-report.md) | Encoded PowerShell | Base64 `-EncodedCommand`, decoded during triage | T1059.001, T1027 | Level 12 |
| [003](Investigations/incident-003-temporary-admin-account/incident-report.md) | Temporary admin account | Account created, elevated, and deleted in 100 ms | T1136.001, T1098, T1070 | Level 12 |

Incident 003 is the most substantive: investigating it found that Wazuh's
built-in mapping for rule `60154` asserts `T1484` (Domain Policy Modification)
for a *local* group change on a non-domain-joined host, which is wrong. It also
exposed that four of the seven events had no behavioural triage rule and were
falling through to a lab-marker label. Both are documented and fixed.

---

## Detection engineering

Eight Sigma rules in [`Detections/sigma/`](Detections/sigma/) and five hunting
queries in [`Detections/wazuh-dql/`](Detections/wazuh-dql/) — one per simulation
scenario, plus the two original PowerShell rules.

Validate them before committing:

```bash
python3 scripts/validate-detections.py
```

This catches the failure that is otherwise invisible: a Sigma condition
referencing a selection block that does not exist, so the rule parses fine and
never fires. It also enforces a policy-pack invariant — lab-simulation markers
(`soc_lab_temp_admin`, `wazuh-powershell-test`) must score below behavioural
rules, or a genuine privilege-escalation detection gets labelled "SOC lab
scenario" instead of "Member added to local Administrators group".

**On bulk rule import.** Sigma is the right portable source, but Sigma rules do
not become native Wazuh 4.x alerts automatically. Either convert them into
OpenSearch hunting queries with `sigma-cli`, or port the high-value subset into
Wazuh XML under `/var/ossec/etc/rules/`, test with `wazuh-logtest`, and restart
the manager.

---

## Publishing a demo

The console reads from a local Wazuh indexer, which cannot be hosted — putting a
SIEM on the public internet to power a portfolio demo would be reckless. Instead,
freeze a point-in-time export of real alerts:

```bash
python3 scripts/export-snapshot.py --anonymize
```

This writes `soc-ai-platform/sample-data/snapshot.json`. When the console loads
with no backend reachable, it serves that snapshot and labels itself "Snapshot"
in the sidebar. Deploy `soc-ai-platform/` as a static site and the queue,
triage, evidence panels, and template analysis all work with real data.

---

## Security notes

This is a lab, and it is configured like one. Before reusing any of it
elsewhere:

- The Wazuh deployment ships stock credentials (`admin` / `SecretPassword`) and
  a self-signed certificate. The console defaults to the same and disables TLS
  verification against `127.0.0.1`.
- The console binds to `127.0.0.1` only and has no authentication.
- Evidence files contain the real lab hostname, username, and local IP.
- `.env`, `wazuh-docker/`, and all `*.key` / `*-key.pem` files are gitignored.

---

## Verify

```bash
cd soc-ai-platform && .venv/bin/python -m unittest discover -p "test_*.py"
```

```bash
python3 scripts/validate-detections.py
```

```bash
node --check soc-ai-platform/app.js
```
