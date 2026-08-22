#!/usr/bin/env python3
"""Investigation assistant for the AI SOC console.

Supports two model backends behind one interface, plus a deterministic
fallback, so the console behaves the same in all three cases:

    claude    Anthropic API. Best output quality, costs a few cents per run.
    ollama    A model running locally. Free, offline, no account.
    template  Field interpolation from templates.py. Always available.

`SOC_AI_PROVIDER` selects one explicitly; the default "auto" prefers Claude
when a credential exists, falls back to a reachable Ollama server, and finally
to templates. Nothing here is a hard dependency: `analyze()` never raises, and
every failure path degrades to the next option down.

Design notes:

- The system prompt is loaded from `AI-Layer/prompts/investigation-summary-prompt.md`
  so the analyst-authored prompt is the one that actually runs, whichever
  backend serves the request.
- Only normalized Wazuh alert fields are sent. No credentials, no host
  filesystem contents, no indexer configuration.
- Local models get a compact evidence rendering instead of raw JSON. Small
  models lose the thread in deeply nested structures, and the compact form
  costs far fewer tokens against a small context window.
- Claude refusals are handled explicitly. This is defensive security work, but
  the evidence contains real attacker-style command lines, so a request can be
  declined by a safety classifier. Server-side fallbacks re-run the request on
  another model inside the same call, and if the whole chain declines we return
  the template output rather than an empty panel.
"""
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import templates

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent

PROVIDER = os.getenv("SOC_AI_PROVIDER", "auto").strip().lower()
MODEL = os.getenv("SOC_AI_MODEL", "claude-opus-5")
EFFORT = os.getenv("SOC_AI_EFFORT", "medium")
MAX_TOKENS = int(os.getenv("SOC_AI_MAX_TOKENS", "4000"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("SOC_AI_OLLAMA_MODEL", "llama3.2:3b")
# Local generation on a small model is slow; this is a ceiling, not a target.
OLLAMA_TIMEOUT = int(os.getenv("SOC_AI_OLLAMA_TIMEOUT", "300"))
OLLAMA_NUM_CTX = int(os.getenv("SOC_AI_OLLAMA_NUM_CTX", "8192"))
# Availability probe. A cold or memory-pressured Ollama can take several
# seconds to answer even /api/tags, and a probe that gives up too early makes
# the console report "AI unavailable" while the model is in fact working.
OLLAMA_PROBE_TIMEOUT = int(os.getenv("SOC_AI_OLLAMA_PROBE_TIMEOUT", "12"))
OLLAMA_PROBE_TTL = 30
_OLLAMA_PROBE_CACHE = {"at": 0.0, "models": None}

PROMPT_PATH = Path(
    os.getenv(
        "SOC_AI_SYSTEM_PROMPT",
        str(PROJECT_ROOT / "AI-Layer" / "prompts" / "investigation-summary-prompt.md"),
    )
).expanduser()

# Per-1M-token rates for the default Claude model, used only to show the analyst
# what a request cost. Local models are free, so cost is reported as zero.
PRICING = {"input": 5.00, "output": 25.00}

ROLE_PREAMBLE = """You are the investigation assistant inside a defensive Security \
Operations Center console.

Context you can rely on:

- This is a self-contained SOC lab. The Windows endpoint is instrumented with \
Sysmon and PowerShell logging, and it is owned and operated by the analyst \
reading your output.
- The telemetry you are shown has already been collected by Wazuh and triaged. \
Your job is post-detection analysis: explain what the recorded evidence shows, \
map it to MITRE ATT&CK, and help the analyst write detection logic and a \
response plan.
- Suspicious-looking command lines in the evidence are recorded observations of \
activity that already happened. Analysing them is the entire point of the tool.

You never generate offensive tooling. You explain observed telemetry, write \
detection rules, and recommend defensive response actions."""

FALLBACK_PROMPT = """Use the provided logs to draft an investigation summary, but do not
invent facts that are not present in the evidence.

- Separate confirmed facts from hypotheses.
- Mention missing evidence explicitly.
- Do not say an incident is malicious unless the logs support that conclusion.
- Keep the final analyst responsible for validation."""

TASK_INSTRUCTIONS = {
    "summary": (
        "Write an executive summary of this alert for a SOC shift handover. "
        "State what was observed, why it was flagged, what it likely means, and "
        "your confidence. Finish with a clear recommendation: close as benign, "
        "keep investigating, or escalate."
    ),
    "timeline": (
        "Reconstruct a chronological timeline of the activity from the alert and "
        "its surrounding events. Use a markdown table with Time, Source, Event, "
        "and Interpretation columns. Mark any gap where telemetry is missing."
    ),
    "mitre": (
        "Map the observed behaviour to MITRE ATT&CK. For each technique give the "
        "ID, name, tactic, the specific evidence field that supports it, and your "
        "confidence. Call out any technique the triage policy asserts that the "
        "evidence does not actually support."
    ),
    "response": (
        "Write an incident response plan. Cover immediate containment, evidence "
        "to collect before it ages out, validation steps to confirm or rule out "
        "compromise, and eradication or recovery. Mark each action as Do Now, "
        "Do If Confirmed, or Follow Up."
    ),
    "detection": (
        "Review the baseline Sigma rule and DQL query supplied above. Restate "
        "them unchanged in fenced code blocks, then assess them: does the "
        "selection target durable behaviour rather than lab-specific markers "
        "like test strings or hostnames? What would this rule miss? What "
        "legitimate activity would it fire on? Recommend specific tuning."
    ),
}

TASK_TITLES = {
    "summary": "Executive summary",
    "timeline": "Timeline",
    "mitre": "MITRE ATT&CK mapping",
    "response": "Response plan",
    "detection": "Detection logic",
    "chat": "Analyst question",
}


def _strip_output_contract(prompt_text):
    """Drop the prompt file's fixed 'Return: 1..6' section list.

    The analyst prompt specifies the shape of a full investigation summary.
    That contract is right for the summary task and wrong for every other one:
    a small local model asked for a Sigma rule will obey the numbered list in
    the system prompt and return another summary instead. The behavioural rules
    ("do not invent facts", "separate fact from hypothesis") always apply, so
    only the section list is removed.
    """
    lowered = prompt_text.lower()
    start = lowered.find("return:")
    if start == -1:
        return prompt_text
    resume = lowered.find("important rules:", start)
    if resume == -1:
        return prompt_text[:start].rstrip()
    return f"{prompt_text[:start].rstrip()}\n\n{prompt_text[resume:].lstrip()}"


def _load_system_prompt(task="summary"):
    """Compose the system prompt from the analyst-authored prompt file."""
    try:
        analyst_rules = PROMPT_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        analyst_rules = FALLBACK_PROMPT
    if task != "summary":
        analyst_rules = _strip_output_contract(analyst_rules)
    return f"{ROLE_PREAMBLE}\n\n---\n\nAnalyst standing instructions:\n\n{analyst_rules}"


def _client():
    """Return an Anthropic client, or None when one cannot be built."""
    try:
        import anthropic
    except ImportError:
        return None
    try:
        return anthropic.Anthropic()
    except Exception:
        # Raised when no credential can be resolved from the environment.
        return None


def _claude_ready():
    """True when the SDK is importable and a credential is present."""
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, "anthropic SDK not installed (pip install -r requirements.txt)"
    if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")):
        return False, "No ANTHROPIC_API_KEY set"
    return True, ""


def _ollama_models(force=False):
    """Return the models the local Ollama server has pulled, or None.

    Successful probes are cached briefly so a single slow response cannot flip
    the console between "AI ready" and "AI unavailable" between page loads.
    """
    now = time.monotonic()
    if (
        not force
        and _OLLAMA_PROBE_CACHE["models"] is not None
        and now - _OLLAMA_PROBE_CACHE["at"] < OLLAMA_PROBE_TTL
    ):
        return _OLLAMA_PROBE_CACHE["models"]

    try:
        request = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(request, timeout=OLLAMA_PROBE_TIMEOUT) as response:
            payload = json.loads(response.read().decode())
        models = [model.get("name", "") for model in payload.get("models", [])]
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None

    _OLLAMA_PROBE_CACHE.update({"at": now, "models": models})
    return models


def _ollama_ready():
    """True when the local server is up and the configured model is pulled."""
    models = _ollama_models()
    if models is None:
        return False, f"No Ollama server at {OLLAMA_URL}"
    if not models:
        return False, f"Ollama is running but has no models (ollama pull {OLLAMA_MODEL})"
    # Ollama reports "llama3.2:3b"; accept a bare family name too.
    if OLLAMA_MODEL not in models and not any(
        name.split(":")[0] == OLLAMA_MODEL.split(":")[0] for name in models
    ):
        return False, f"Model {OLLAMA_MODEL} not pulled (ollama pull {OLLAMA_MODEL})"
    return True, ""


def resolve_provider():
    """Pick the backend to use. Returns (provider, model_label, reason)."""
    if PROVIDER == "template":
        return "template", "", "Provider pinned to template mode"

    if PROVIDER in ("claude", "auto"):
        ready, why = _claude_ready()
        if ready:
            return "claude", MODEL, ""
        if PROVIDER == "claude":
            return "template", "", f"{why}; using evidence templates"
        claude_reason = why
    else:
        claude_reason = ""

    if PROVIDER in ("ollama", "auto"):
        ready, why = _ollama_ready()
        if ready:
            return "ollama", OLLAMA_MODEL, ""
        if PROVIDER == "ollama":
            return "template", "", f"{why}; using evidence templates"
        joined = "; ".join(part for part in (claude_reason, why) if part)
        return "template", "", f"{joined}; using evidence templates"

    return "template", "", "No model backend available; using evidence templates"


def status():
    """Report which backend will serve requests, for /api/health."""
    provider, model, reason = resolve_provider()
    state = {
        "enabled": provider != "template",
        "provider": provider,
        "model": model,
        "reason": reason,
    }
    if provider == "claude":
        state["effort"] = EFFORT
        state["cost"] = "billed per token"
    elif provider == "ollama":
        state["cost"] = "free (local)"
    return state


def _compact_event(event):
    """One dense line per surrounding event, to keep context cheap."""
    parts = [
        event.get("timestamp", "")[:23],
        f"rule {event.get('rule', {}).get('id', '?')}",
        f"level {event.get('rule', {}).get('level', '?')}",
        event.get("rule", {}).get("description", ""),
    ]
    command = event.get("process", {}).get("commandLine", "")
    if command:
        parts.append(f"cmd: {command[:200]}")
    return " | ".join(str(part) for part in parts if part)


def _compact_alert(alert):
    """Flatten the alert to labelled lines for small-context local models."""
    rule = alert.get("rule", {})
    event = alert.get("event", {})
    process = alert.get("process", {})
    account = alert.get("account", {})
    triage = alert.get("triage", {})

    fields = [
        ("Time", alert.get("timestamp")),
        ("Endpoint", alert.get("agent", {}).get("name")),
        ("Endpoint IP", alert.get("agent", {}).get("ip")),
        ("Wazuh rule", f"{rule.get('id')} - {rule.get('description')}"),
        ("Rule level", rule.get("level")),
        ("Wazuh MITRE", f"{rule.get('mitreId')} {rule.get('mitreTechnique')} ({rule.get('mitreTactic')})"),
        ("Log channel", event.get("channel")),
        ("Windows Event ID", event.get("eventId")),
        ("Process image", process.get("image")),
        ("Parent image", process.get("parentImage")),
        ("Command line", process.get("commandLine")),
        ("User", process.get("user")),
        ("Working directory", process.get("currentDirectory")),
        ("Account action", account.get("action")),
        ("Actor", account.get("actor")),
        ("Target account", account.get("targetUser")),
        ("Group", account.get("groupName")),
        ("Member SID", account.get("memberSid")),
        ("Triage status", triage.get("status")),
        ("Triage reason", triage.get("reason")),
        ("Triage policy", triage.get("policyRule")),
        # Spell out the technique names rather than leaving bare IDs. Small
        # models reliably invent a plausible-sounding name for an ID they are
        # given on its own (T1027 came back as "Living off the Land").
        ("Applicable MITRE techniques", "; ".join(templates.mitre_labels(alert))),
    ]
    return "\n".join(f"{label}: {value}" for label, value in fields if value not in (None, "", []))


def build_evidence(alert, context_events=None, compact=False):
    """Render the alert and its context as a factual evidence block.

    `compact` swaps the raw JSON for labelled lines. Small local models follow
    that far better than nested JSON, and it costs a fraction of the tokens.
    """
    decoded = templates.decoded_powershell(alert)
    if compact:
        sections = ["## Alert evidence", "```text", _compact_alert(alert), "```"]
    else:
        sections = [
            "## Primary alert (normalized Wazuh document)",
            "```json",
            json.dumps(alert, indent=2, ensure_ascii=False),
            "```",
        ]

    if decoded:
        sections += [
            "",
            "## Decoded PowerShell payload",
            "The base64 in the command line above decodes to:",
            "```powershell",
            decoded,
            "```",
        ]

    if context_events:
        lines = [_compact_event(event) for event in context_events[:20]]
        sections += [
            "",
            f"## Surrounding events on the same endpoint ({len(lines)} shown, +/- 10 minutes)",
            "```text",
            "\n".join(lines),
            "```",
        ]
    else:
        sections += [
            "",
            "## Surrounding events",
            "Not loaded. Treat the absence of context as unknown, not as absence of activity.",
        ]

    return "\n".join(sections)


def _template_result(alert, context_events, task, question, reason):
    """Deterministic fallback so the console always renders something."""
    return {
        "mode": "template",
        "task": task,
        "title": TASK_TITLES.get(task, "Analysis"),
        "text": templates.render(alert, context_events, task, question),
        "model": "",
        "reason": reason,
        "usage": {},
    }


def _build_instruction(task, question):
    if task == "chat":
        return (
            "Answer the analyst's question using only the evidence above. If the "
            "evidence cannot answer it, say so and name the telemetry that would.\n\n"
            f"Analyst question: {question}"
        )
    return TASK_INSTRUCTIONS.get(task, TASK_INSTRUCTIONS["summary"])


def _detection_baseline(alert):
    """Supply the mechanically-generated rule for the model to critique.

    Sigma has a strict schema, and a small local model asked to write one from
    memory invents fields that do not exist. templates.py already emits valid
    Sigma and DQL from the alert, so the model's job is the part it is actually
    good at: judging whether the selection is well chosen, what it would miss,
    and where it would fire falsely.
    """
    return (
        "\n\n## Baseline detection generated from this alert\n\n"
        "This Sigma rule and DQL query were produced mechanically from the "
        "evidence above. They are syntactically valid. Do not rewrite them from "
        "scratch.\n\n"
        f"```yaml\n{templates.sigma_for(alert)}\n```\n\n"
        f"```text\n{templates.dql_for(alert)}\n```"
    )


def _user_content(alert, context_events, task, question, compact=False):
    instruction = _build_instruction(task, question)
    # Small local models overreach: they escalate discovery commands into
    # "lateral movement" and invent MITRE names. The extra guardrails below are
    # only sent to them; Claude follows the standing analyst instructions.
    closing = (
        "Respond in markdown. Be specific and cite the evidence fields you used."
        if not compact
        else (
            "Respond in markdown. Rules you must follow:\n"
            "- Use only the facts listed above. Never invent field values.\n"
            "- Use only the MITRE techniques listed under 'Applicable MITRE "
            "techniques', with exactly those IDs and names. Do not add others.\n"
            "- Do not claim lateral movement, command and control, data theft, "
            "persistence, or compromise unless a field above directly shows it.\n"
            "- Describe what the evidence shows, then state your confidence.\n"
            "- Be concise."
        )
    )
    baseline = _detection_baseline(alert) if task == "detection" else ""
    return (
        f"{build_evidence(alert, context_events, compact=compact)}"
        f"{baseline}\n\n"
        f"---\n\n## Task\n\n{instruction}\n\n{closing}"
    )


def _analyze_claude(alert, context_events, task, question):
    client = _client()
    if client is None:
        return _template_result(
            alert, context_events, task, question, "Could not build an Anthropic client"
        )

    try:
        with client.beta.messages.stream(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=_load_system_prompt(task),
            thinking={"type": "adaptive"},
            output_config={"effort": EFFORT},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[
                {"role": "user", "content": _user_content(alert, context_events, task, question)}
            ],
        ) as stream:
            message = stream.get_final_message()
    except Exception as error:
        return _template_result(
            alert, context_events, task, question, f"Claude request failed: {error}"
        )

    # Check the stop reason before reading content: a refused turn can carry no
    # usable text at all.
    if message.stop_reason == "refusal":
        category = getattr(message.stop_details, "category", None) or "unspecified"
        return _template_result(
            alert,
            context_events,
            task,
            question,
            f"Model declined this request (category: {category}); showing template output",
        )

    text = "\n\n".join(
        block.text for block in message.content if block.type == "text"
    ).strip()
    if not text:
        return _template_result(
            alert, context_events, task, question, "Empty model response"
        )

    usage = message.usage
    input_tokens = getattr(usage, "input_tokens", 0) or 0
    output_tokens = getattr(usage, "output_tokens", 0) or 0
    cost = (
        input_tokens * PRICING["input"] + output_tokens * PRICING["output"]
    ) / 1_000_000

    return {
        "mode": "claude",
        "task": task,
        "title": TASK_TITLES.get(task, "Analysis"),
        "text": text,
        "model": message.model,
        "reason": "",
        "usage": {
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "costUsd": round(cost, 4),
        },
    }


def _analyze_ollama(alert, context_events, task, question):
    body = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "stream": False,
            "messages": [
                {"role": "system", "content": _load_system_prompt(task)},
                {
                    "role": "user",
                    "content": _user_content(
                        alert, context_events, task, question, compact=True
                    ),
                },
            ],
            "options": {
                # Low temperature: this is evidence reporting, not creative writing.
                "temperature": 0.2,
                "num_ctx": OLLAMA_NUM_CTX,
                "num_predict": 1200,
            },
        }
    ).encode()

    request = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT) as response:
            payload = json.loads(response.read().decode())
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as error:
        return _template_result(
            alert, context_events, task, question, f"Ollama request failed: {error}"
        )

    text = (payload.get("message", {}).get("content") or "").strip()
    if not text:
        return _template_result(
            alert, context_events, task, question, "Empty response from the local model"
        )

    duration_ns = payload.get("total_duration") or 0
    return {
        "mode": "ollama",
        "task": task,
        "title": TASK_TITLES.get(task, "Analysis"),
        "text": text,
        "model": payload.get("model", OLLAMA_MODEL),
        "reason": "",
        "usage": {
            "inputTokens": payload.get("prompt_eval_count", 0) or 0,
            "outputTokens": payload.get("eval_count", 0) or 0,
            "costUsd": 0.0,
            "seconds": round(duration_ns / 1_000_000_000, 1) if duration_ns else 0,
        },
    }


def analyze(alert, context_events=None, task="summary", question=""):
    """Produce an investigation artifact for one alert.

    Returns a dict with `text`, `mode` ("claude", "ollama", or "template"), the
    model used, and usage. Never raises: every failure degrades to the template
    renderer so the console always has something to render.
    """
    provider, _model, reason = resolve_provider()

    if provider == "claude":
        return _analyze_claude(alert, context_events, task, question)
    if provider == "ollama":
        return _analyze_ollama(alert, context_events, task, question)
    return _template_result(alert, context_events, task, question, reason)
