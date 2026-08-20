# AI SOC Analyst Console

A local live Wazuh dashboard for investigating security alerts with a free evidence-bound AI assistant.

## How It Works

The local backend reads from your Wazuh Indexer at `https://127.0.0.1:9200` and serves normalized alerts to the browser through `/api/alerts`.

The AI assistant is still free demo mode. It does not call a paid AI API. It drafts summaries, timelines, MITRE notes, response plans, and detection ideas from the selected alert fields.

Detection and AI are deliberately separate:

- Wazuh and Sysmon collect telemetry and generate alerts.
- `rules/triage-rules.json` ranks those alerts as candidates, review items, or noise.
- The AI assistant investigates the selected evidence; it is not the detection engine.

The triage policy file is reloaded automatically when it changes. Each matched
alert includes the policy rule ID, title, score, MITRE mappings, and all matching
policy rules. Inspect the active pack at:

```text
http://127.0.0.1:5174/api/rules
```

Later, the same UI can be connected to:

- Wazuh API
- OpenSearch/Wazuh alerts index
- Postgres/Supabase
- OpenAI or another hosted LLM

## Run Locally

From this folder:

```bash
python3 server.py
```

Open:

```text
http://127.0.0.1:5174
```

Optional environment variables:

```bash
export WAZUH_INDEXER_URL="https://127.0.0.1:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="SecretPassword"
export WAZUH_MIN_LEVEL="4"
export SOC_TRIAGE_RULE_PACK="/absolute/path/to/triage-rules.json"
```

## Generate Lab Telemetry

The safe scenario runner is stored at:

```text
../Simulations/Invoke-SocLabScenario.ps1
```

Run one scenario from an Administrator PowerShell window in the Windows VM:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
Z:\Simulations\Invoke-SocLabScenario.ps1 -Scenario EncodedPowerShell
```

Available scenarios are `EncodedPowerShell`, `DiscoveryBurst`,
`ScheduledTask`, `RunKey`, `Certutil`, `TemporaryAdmin`, and `All`.
Temporary scheduled tasks, Run values, files, and accounts are removed by the
script.

## Bulk Rule Strategy

Do not place thousands of detection rules inside an LLM prompt. Wazuh already
applies its built-in rules before the dashboard receives an alert. Add larger
Wazuh XML rule packs under the manager's persistent `/var/ossec/etc/rules/`
directory, test them with `wazuh-logtest`, and restart the manager.

Sigma is useful as a portable rule source. With Wazuh 4.x, use `sigma-cli` and
an OpenSearch backend to convert Sigma rules into hunting queries, or port the
small high-value subset that must generate native Wazuh alerts into Wazuh XML.
The local JSON policy pack is for post-alert prioritization, not a replacement
for the Wazuh or Sigma detection engines.

## Verify

```bash
python3 -m unittest test_server.py
python3 -m py_compile server.py
node --check app.js
```

## Demo Incident

The bundled sample alert is based on Incident 001 from the SOC lab:

- Wazuh rule `92027`
- Sysmon Event ID `1`
- `Powershell process spawned powershell instance`
- MITRE `T1059.001`
