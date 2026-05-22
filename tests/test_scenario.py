from unittest import TestCase

from findevil_sift.scenario import render_case_dossier


class ScenarioReportTests(TestCase):
    def test_case_dossier_renders_profile_and_alignment(self) -> None:
        report = render_case_dossier(
            {
                "generated_at": "2026-05-22T00:00:00Z",
                "passed": True,
                "score": {"passed_checks": 1, "total_checks": 1},
                "profile": {
                    "case_name": "Case",
                    "case_owner": "Source",
                    "case_context": ["Context"],
                    "artifact_roles": [{"artifact": "PCAP", "role": "Network"}],
                    "references": ["Reference"],
                },
                "checks": [
                    {
                        "name": "payload_delivery",
                        "passed": True,
                        "expected": "payload",
                        "observed": "payload",
                    }
                ],
                "evidence_notes": ["Review preserved outputs."],
            }
        )
        self.assertIn("Case Dossier", report)
        self.assertIn("payload_delivery", report)
