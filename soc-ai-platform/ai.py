#!/usr/bin/env python3
"""Claude-backed investigation assistant for the AI SOC console.

The console never depends on this module being usable. When the Anthropic SDK
is missing or no credential is configured, `analyze()` falls back to the
deterministic evidence templates in `templates.py`, so the dashboard behaves
identically minus the model-written analysis.

Design notes:

- The system prompt is loaded from `AI-Layer/prompts/investigation-summary-prompt.md`
  so the analyst-authored prompt is the one that actually runs.
- Only normalized Wazuh alert fields are sent. No credentials, no host
  filesystem contents, no indexer configuration.
- Refusals are handled explicitly. This is defensive security work, but the
  evidence contains real attacker-style command lines, so a request can be
  declined by a safety classifier. Server-side fallbacks re-run the request on
  another model inside the same call, and if the whole chain declines we return
  the template output rather than an empty panel.
"""
import json
import os
from pathlib import Path

import templates

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent

MODEL = os.getenv("SOC_AI_MODEL", "claude-opus-5")
EFFORT = os.getenv("SOC_AI_EFFORT", "medium")
MAX_TOKENS = int(os.getenv("SOC_AI_MAX_TOKENS", "4000"))
PROMPT_PATH = Path(
    os.getenv(
        "SOC_AI_SYSTEM_PROMPT",
        str(PROJECT_ROOT / "AI-Layer" / "prompts" / "investigation-summary-prompt.md"),
    )
).expanduser()

# Per-1M-token rates for the default model, used only to show the analyst what a
# request cost. Update if you switch models.
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
        "Write detection logic for this behaviour. Provide a complete Sigma rule "
        "in YAML and an equivalent Wazuh DQL query. Base the selection criteria "
        "on the durable behaviour, not on lab-specific markers such as test "
        "strings or hostnames. List realistic false positives."
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


def _load_system_prompt():
    """Compose the system prompt from the analyst-authored prompt file."""
    try:
        analyst_rules = PROMPT_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        analyst_rules = FALLBACK_PROMPT
    return f"{ROLE_PREAMBLE}\n\n---\n\nAnalyst standing instructions:\n\n{analyst_rules}"


def _client():
    """Return an Anthropic client, or None when the AI layer is unavailable."""
    try:
        import anthropic
    except ImportError:
        return None
    try:
        return anthropic.Anthropic()
    except Exception:
        # Raised when no credential can be resolved from the environment.
        return None


def status():
    """Report whether the AI layer can serve requests, for /api/health."""
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return {
            "enabled": False,
            "reason": "anthropic SDK not installed (pip install -r requirements.txt)",
            "model": MODEL,
        }
    if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")):
        return {
            "enabled": False,
            "reason": "No ANTHROPIC_API_KEY set; using evidence templates",
            "model": MODEL,
        }
    return {"enabled": True, "reason": "", "model": MODEL, "effort": EFFORT}


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


def build_evidence(alert, context_events=None):
    """Render the alert and its context as a factual evidence block."""
    decoded = templates.decoded_powershell(alert)
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


def analyze(alert, context_events=None, task="summary", question=""):
    """Produce an investigation artifact for one alert.

    Returns a dict with `text`, `mode` ("claude" or "template"), and usage.
    Never raises: any failure degrades to the template renderer.
    """
    availability = status()
    if not availability["enabled"]:
        return _template_result(
            alert, context_events, task, question, availability["reason"]
        )

    client = _client()
    if client is None:
        return _template_result(
            alert, context_events, task, question, "Could not build an Anthropic client"
        )

    if task == "chat":
        instruction = (
            "Answer the analyst's question using only the evidence above. If the "
            "evidence cannot answer it, say so and name the telemetry that would.\n\n"
            f"Analyst question: {question}"
        )
    else:
        instruction = TASK_INSTRUCTIONS.get(task, TASK_INSTRUCTIONS["summary"])

    user_content = (
        f"{build_evidence(alert, context_events)}\n\n"
        f"---\n\n## Task\n\n{instruction}\n\n"
        "Respond in markdown. Be specific and cite the evidence fields you used."
    )

    try:
        with client.beta.messages.stream(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=_load_system_prompt(),
            thinking={"type": "adaptive"},
            output_config={"effort": EFFORT},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": user_content}],
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
