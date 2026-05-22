from unittest import TestCase

from findevil_sift.reports import render_userassist_report


class UserAssistReportTests(TestCase):
    def test_report_surfaces_execution_entries_and_review_candidates(self) -> None:
        report = render_userassist_report(
            {
                "evidence": {
                    "path": "/cases/protected.zip",
                    "before_sha256": "a",
                    "after_sha256": "a",
                    "unchanged": True,
                },
                "userassist": {
                    "profiles": [
                        {
                            "profile": "Administrator",
                            "member": "Users/Administrator/NTUSER.DAT",
                            "entry_count": 1,
                            "raw_output": "administrator-userassist.txt",
                        }
                    ],
                    "execution_entries": [
                        {
                            "profile": "Administrator",
                            "timestamp": "2020-09-19 03:56:37Z",
                            "entry": r"{GUID}\coreupdater.exe",
                            "run_count": 3,
                            "executable_name": "coreupdater.exe",
                        }
                    ],
                    "review_candidates": [
                        {
                            "profile": "Administrator",
                            "timestamp": "2020-09-18 03:50:37Z",
                            "entry": r"{GUID}\powershell.exe",
                            "run_count": 3,
                            "review_reason": "lolbin_or_remote_access_execution_pivot",
                        }
                    ],
                },
                "observations": ["UserAssist preserved execution context."],
            }
        )

        self.assertIn("UserAssist Triage", report)
        self.assertIn("coreupdater.exe", report)
        self.assertIn("powershell.exe", report)
