"""Tests for the AI layer and its deterministic template fallback.

None of these tests call the Claude API. They cover the fallback path, the
evidence builder, and the template renderer, which is exactly the code that has
to stay correct when the model is unavailable.
"""
import os
import unittest

import ai
import templates

ENCODED = (
    "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMATwBDAC0ATABBAEIALQBFAE4A"
    "QwBPAEQARQBEAC0AMAAwADEAJwA7ACAAdwBoAG8AYQBtAGkA"
)


def encoded_alert():
    return {
        "id": "enc-001",
        "index": "wazuh-alerts-4.x-2026.07.23",
        "timestamp": "2026-07-23T07:12:44.101+0000",
        "agent": {"id": "001", "name": "WIN11-SOC-ENDPOINT", "ip": "192.168.64.3"},
        "rule": {
            "id": "92057",
            "level": 12,
            "description": "Powershell executed a base64 encoded command",
            "groups": ["sysmon", "windows"],
            "mitreId": "T1059.001",
            "mitreTactic": "Execution",
            "mitreTechnique": "PowerShell",
        },
        "event": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "eventId": "1",
            "provider": "Microsoft-Windows-Sysmon",
            "message": "",
        },
        "process": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "commandLine": f"powershell.exe -NoProfile -EncodedCommand {ENCODED}",
            "user": "WIN11-SOC-ENDPOINT\\Shams",
        },
        "triage": {
            "status": "candidate",
            "score": 98,
            "reason": "PowerShell encoded command detected",
            "policyRule": "SOC-PS-002",
            "mitre": ["T1059.001", "T1027"],
        },
    }


class TemplateTests(unittest.TestCase):
    def test_decodes_encoded_powershell(self):
        decoded = templates.decoded_powershell(encoded_alert())
        self.assertEqual(decoded, "Write-Output 'SOC-LAB-ENCODED-001'; whoami")

    def test_decode_returns_empty_for_plain_command(self):
        alert = encoded_alert()
        alert["process"]["commandLine"] = "powershell.exe -NoProfile -Command whoami"
        self.assertEqual(templates.decoded_powershell(alert), "")

    def test_decode_survives_invalid_base64(self):
        alert = encoded_alert()
        alert["process"]["commandLine"] = "powershell.exe -enc !!!!notbase64!!!!"
        self.assertEqual(templates.decoded_powershell(alert), "")

    def test_mitre_labels_merge_wazuh_and_policy(self):
        labels = templates.mitre_labels(encoded_alert())
        self.assertIn("T1059.001 - PowerShell", labels)
        self.assertIn("T1027 - Obfuscated Files or Information", labels)

    def test_sigma_targets_behaviour_not_lab_markers(self):
        sigma = templates.sigma_for(encoded_alert())
        self.assertIn("Image|endswith: '\\powershell.exe'", sigma)
        self.assertIn("-EncodedCommand", sigma)
        self.assertIn("attack.t1027", sigma)
        self.assertNotIn("SOC-LAB", sigma.upper().replace("SOC-LAB-ENCODED", ""))

    def test_dql_includes_event_id_and_image(self):
        dql = templates.dql_for(encoded_alert())
        self.assertIn("data.win.system.eventID: 1", dql)
        self.assertIn("powershell.exe", dql)

    def test_report_embeds_decoded_payload(self):
        report = templates.report_for(encoded_alert())
        self.assertIn("Decoded PowerShell Payload", report)
        self.assertIn("SOC-LAB-ENCODED-001", report)

    def test_every_task_renders_non_empty(self):
        alert = encoded_alert()
        for task in ("summary", "timeline", "mitre", "response", "detection", "chat"):
            with self.subTest(task=task):
                text = templates.render(alert, [], task, "what happened?")
                self.assertTrue(text.strip())
                self.assertIn("template engine", text)


class EvidenceTests(unittest.TestCase):
    def test_evidence_includes_decoded_payload(self):
        evidence = ai.build_evidence(encoded_alert(), [])
        self.assertIn("Decoded PowerShell payload", evidence)
        self.assertIn("SOC-LAB-ENCODED-001", evidence)

    def test_evidence_flags_missing_context(self):
        evidence = ai.build_evidence(encoded_alert(), [])
        self.assertIn("Not loaded", evidence)

    def test_evidence_summarizes_context_events(self):
        context = [
            {
                "timestamp": "2026-07-23T07:12:40.000+0000",
                "rule": {"id": "61603", "level": 3, "description": "Windows service started"},
                "process": {"commandLine": "svchost.exe -k netsvcs"},
            }
        ]
        evidence = ai.build_evidence(encoded_alert(), context)
        self.assertIn("Surrounding events on the same endpoint (1 shown", evidence)
        self.assertIn("Windows service started", evidence)

    def test_system_prompt_loads_analyst_file(self):
        prompt = ai._load_system_prompt()
        self.assertIn("Security Operations Center", prompt)
        # Sourced from AI-Layer/prompts/investigation-summary-prompt.md
        self.assertIn("do not invent facts", prompt.lower())


class FallbackTests(unittest.TestCase):
    """Degradation when a backend is unavailable.

    These pin SOC_AI_PROVIDER rather than relying on an absent API key. Since
    Ollama became a supported backend, "no ANTHROPIC_API_KEY" no longer implies
    template mode: on a machine with a local model running, auto correctly
    resolves to ollama instead.
    """

    def setUp(self):
        self._saved = {
            key: os.environ.pop(key, None)
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
        }
        self._provider = ai.PROVIDER

    def tearDown(self):
        ai.PROVIDER = self._provider
        for key, value in self._saved.items():
            if value is not None:
                os.environ[key] = value

    def test_analyze_falls_back_without_credentials(self):
        ai.PROVIDER = "claude"
        result = ai.analyze(encoded_alert(), [], "summary")
        self.assertEqual(result["mode"], "template")
        self.assertIn("ANTHROPIC_API_KEY", result["reason"])
        self.assertTrue(result["text"].strip())

    def test_status_reports_disabled_without_any_backend(self):
        ai.PROVIDER = "template"
        state = ai.status()
        self.assertFalse(state["enabled"])
        self.assertTrue(state["reason"])
        self.assertEqual(state["provider"], "template")

    def test_unreachable_ollama_degrades_to_template(self):
        ai.PROVIDER = "ollama"
        saved_url = ai.OLLAMA_URL
        ai.OLLAMA_URL = "http://127.0.0.1:59999"  # nothing listens here
        try:
            result = ai.analyze(encoded_alert(), [], "summary")
            self.assertEqual(result["mode"], "template")
            self.assertTrue(result["text"].strip())
        finally:
            ai.OLLAMA_URL = saved_url


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self._saved = {
            key: os.environ.pop(key, None)
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
        }
        self._provider = ai.PROVIDER

    def tearDown(self):
        ai.PROVIDER = self._provider
        for key, value in self._saved.items():
            if value is not None:
                os.environ[key] = value

    def test_template_provider_is_honoured(self):
        ai.PROVIDER = "template"
        provider, _model, reason = ai.resolve_provider()
        self.assertEqual(provider, "template")
        self.assertTrue(reason)

    def test_claude_provider_without_key_degrades_to_template(self):
        ai.PROVIDER = "claude"
        provider, _model, reason = ai.resolve_provider()
        self.assertEqual(provider, "template")
        self.assertIn("ANTHROPIC_API_KEY", reason)

    def test_analyze_never_raises_for_any_provider(self):
        alert = encoded_alert()
        for provider in ("template", "claude", "ollama", "auto", "nonsense"):
            with self.subTest(provider=provider):
                ai.PROVIDER = provider
                result = ai.analyze(alert, [], "summary")
                self.assertIn(result["mode"], {"template", "claude", "ollama"})
                self.assertTrue(result["text"].strip())


class PromptShapingTests(unittest.TestCase):
    def test_summary_keeps_the_output_contract(self):
        prompt = ai._load_system_prompt("summary")
        self.assertIn("Executive summary", prompt)

    def test_other_tasks_drop_the_output_contract(self):
        # A small model otherwise obeys the numbered section list in the system
        # prompt and returns a summary when asked for a Sigma rule.
        prompt = ai._load_system_prompt("detection")
        self.assertNotIn("Executive summary", prompt)

    def test_behavioural_rules_survive_stripping(self):
        for task in ("summary", "detection", "mitre"):
            with self.subTest(task=task):
                prompt = ai._load_system_prompt(task).lower()
                self.assertIn("do not invent facts", prompt)
                self.assertIn("responsible for validation", prompt)

    def test_strip_is_a_noop_without_a_contract(self):
        text = "Just rules.\n\n- Do not invent facts."
        self.assertEqual(ai._strip_output_contract(text), text)


class CompactEvidenceTests(unittest.TestCase):
    def test_compact_evidence_names_mitre_techniques(self):
        # Bare IDs make small models invent names (T1027 came back as
        # "Living off the Land"), so the names are supplied.
        evidence = ai.build_evidence(encoded_alert(), [], compact=True)
        self.assertIn("T1027 - Obfuscated Files or Information", evidence)
        self.assertIn("T1059.001 - PowerShell", evidence)

    def test_compact_evidence_has_no_raw_json_dump(self):
        evidence = ai.build_evidence(encoded_alert(), [], compact=True)
        self.assertNotIn('"triage":', evidence)
        self.assertIn("Triage status: candidate", evidence)

    def test_compact_evidence_keeps_the_decoded_payload(self):
        evidence = ai.build_evidence(encoded_alert(), [], compact=True)
        self.assertIn("SOC-LAB-ENCODED-001", evidence)

    def test_detection_baseline_is_valid_sigma(self):
        baseline = ai._detection_baseline(encoded_alert())
        for key in ("logsource:", "detection:", "condition:", "level:"):
            self.assertIn(key, baseline)
        self.assertIn("data.win.system.eventID", baseline)

    def test_detection_task_supplies_the_baseline(self):
        content = ai._user_content(encoded_alert(), [], "detection", "", compact=True)
        self.assertIn("Baseline detection generated from this alert", content)

    def test_other_tasks_do_not_supply_a_baseline(self):
        content = ai._user_content(encoded_alert(), [], "summary", "", compact=True)
        self.assertNotIn("Baseline detection generated", content)


if __name__ == "__main__":
    unittest.main()
