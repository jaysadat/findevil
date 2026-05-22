from unittest import TestCase

from findevil_sift.reports import render_registry_report


class RegistryReportTests(TestCase):
    def test_report_surfaces_high_signal_registry_pivots(self) -> None:
        report = render_registry_report(
            {
                "evidence": {
                    "path": "/cases/protected.zip",
                    "before_sha256": "a",
                    "after_sha256": "a",
                    "unchanged": True,
                },
                "registry": {
                    "hive_members": ["Protected/software", "Protected/system"],
                    "run_entries": [{"name": "coreupdate", "command": "powershell -nop"}],
                    "service_entries": [
                        {
                            "name": "coreupdater",
                            "image_path": r"C:\Windows\System32\coreupdater.exe",
                            "type": "Own_Process",
                            "start": "Auto Start",
                        }
                    ],
                    "high_signal_candidates": [
                        {
                            "entry": "coreupdate",
                            "kind": "run_value",
                            "value": "powershell -nop",
                            "high_signal_reasons": "payload_like_run_command",
                        }
                    ],
                    "decoded_payload_chains": [
                        {
                            "key_path": "9sEoCawv",
                            "value_name": "45SVAG2o",
                            "run_entry": "coreupdate",
                            "outer_script": {"indicators": ["GzipStream"]},
                            "nested_script": {"indicators": ["VirtualAlloc", "CreateThread"]},
                        }
                    ],
                },
                "observations": ["Review the registry pivots."],
            }
        )
        self.assertIn("coreupdate", report)
        self.assertIn("45SVAG2o", report)
        self.assertIn("Protected Registry", report)
