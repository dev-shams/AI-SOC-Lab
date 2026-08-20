#!/usr/bin/env python3
"""Validate the Sigma rules and the triage policy pack.

Catches the mistakes that are easy to make by hand and invisible until a rule
silently never fires: a condition referencing a selection block that does not
exist, a missing required field, a duplicate rule ID, or a triage rule whose
match block would match every alert.

Usage:
    python3 scripts/validate-detections.py

Requires PyYAML (pip install pyyaml).
"""
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = PROJECT_ROOT / "Detections" / "sigma"
RULE_PACK = PROJECT_ROOT / "soc-ai-platform" / "rules" / "triage-rules.json"

REQUIRED_SIGMA_FIELDS = {"title", "description", "logsource", "detection", "level"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
CONDITION_KEYWORDS = {"and", "or", "not", "all", "of", "them", "1", "1_of", "all_of"}

failures = []
warnings = []


def check_sigma():
    seen_ids = {}
    files = sorted(SIGMA_DIR.glob("*.yml")) + sorted(SIGMA_DIR.glob("*.yaml"))
    if not files:
        failures.append(f"No Sigma rules found in {SIGMA_DIR}")
        return

    for path in files:
        name = path.name
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            failures.append(f"{name}: YAML parse error: {error}")
            continue

        if not isinstance(rule, dict):
            failures.append(f"{name}: top level is not a mapping")
            continue

        missing = REQUIRED_SIGMA_FIELDS - set(rule)
        if missing:
            failures.append(f"{name}: missing required field(s): {', '.join(sorted(missing))}")

        level = rule.get("level")
        if level and level not in VALID_LEVELS:
            failures.append(f"{name}: level '{level}' is not one of {sorted(VALID_LEVELS)}")

        rule_id = rule.get("id")
        if rule_id:
            if rule_id in seen_ids:
                failures.append(f"{name}: duplicate rule id, already used by {seen_ids[rule_id]}")
            seen_ids[rule_id] = name

        detection = rule.get("detection")
        if not isinstance(detection, dict):
            failures.append(f"{name}: detection block is missing or not a mapping")
            continue

        condition = detection.get("condition")
        if not condition:
            failures.append(f"{name}: detection.condition is missing")
            continue

        selections = {key for key in detection if key != "condition"}
        if not selections:
            failures.append(f"{name}: detection has a condition but no selection blocks")
            continue

        referenced = {
            token
            for token in str(condition).replace("(", " ").replace(")", " ").split()
            if token.lower() not in CONDITION_KEYWORDS
        }
        unknown = referenced - selections
        if unknown:
            failures.append(
                f"{name}: condition references undefined selection(s): {', '.join(sorted(unknown))}"
            )

        unused = selections - referenced
        if unused and not any(token.lower() in CONDITION_KEYWORDS for token in str(condition).split()):
            warnings.append(f"{name}: selection block(s) never used in condition: {', '.join(sorted(unused))}")

        if not rule.get("falsepositives"):
            warnings.append(f"{name}: no falsepositives listed")

        if not rule.get("tags"):
            warnings.append(f"{name}: no ATT&CK tags")

    print(f"Sigma: checked {len(files)} rule file(s)")


def check_rule_pack():
    try:
        pack = json.loads(RULE_PACK.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"{RULE_PACK.name}: {error}")
        return

    rules = pack.get("rules", [])
    seen = set()
    match_keys = {
        "any_text", "all_text", "exclude_text", "rule_ids", "event_ids",
        "channels", "mitre_ids", "groups_any", "min_level", "max_level",
    }

    for rule in rules:
        rule_id = rule.get("id", "<no id>")
        if rule_id in seen:
            failures.append(f"triage pack: duplicate rule id {rule_id}")
        seen.add(rule_id)

        if rule.get("status") not in {"candidate", "review", "noise"}:
            failures.append(f"triage pack: {rule_id} has invalid status {rule.get('status')!r}")

        score = rule.get("score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            failures.append(f"triage pack: {rule_id} score must be an int 0-100, got {score!r}")

        match = rule.get("match", {})
        if not isinstance(match, dict) or not match:
            failures.append(f"triage pack: {rule_id} has an empty match block (would never fire)")
            continue

        usable = set(match) & match_keys
        if not usable:
            failures.append(
                f"triage pack: {rule_id} match block has no recognized keys "
                f"(has: {', '.join(sorted(match))}) and would never fire"
            )

        # A match block containing only exclude_text matches every alert that
        # is not excluded, which is almost never intended.
        if usable == {"exclude_text"}:
            failures.append(f"triage pack: {rule_id} matches on exclude_text alone, which matches everything")

    # Lab-marker rules must not outrank behavioural rules, or the analyst-facing
    # label becomes "SOC lab scenario" instead of the observed behaviour.
    lab_rules = [r for r in rules if "lab" in r.get("title", "").lower()]
    behavioural = [r for r in rules if r not in lab_rules and r.get("status") == "candidate"]
    if lab_rules and behavioural:
        top_lab = max(r.get("score", 0) for r in lab_rules)
        lowest_behavioural = min(r.get("score", 0) for r in behavioural)
        if top_lab >= lowest_behavioural:
            warnings.append(
                f"triage pack: a lab-marker rule scores {top_lab}, at or above the lowest "
                f"behavioural candidate ({lowest_behavioural}); lab markers may win the primary label"
            )

    print(f"Triage pack: checked {len(rules)} rule(s), version {pack.get('version')}")


def main():
    check_sigma()
    check_rule_pack()

    for warning in warnings:
        print(f"  WARN  {warning}")
    for failure in failures:
        print(f"  FAIL  {failure}")

    print()
    if failures:
        print(f"{len(failures)} failure(s), {len(warnings)} warning(s)")
        return 1
    print(f"All checks passed ({len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
