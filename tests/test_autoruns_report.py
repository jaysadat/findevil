from unittest import TestCase

from findevil_sift.reports import render_autoruns_report


class AutorunsReportTests(TestCase):
    def test_report_surfaces_candidates(self) -> None:
        report = render_autoruns_report(
            {
                "evidence": {
                    "path": "/cases/autoruns.zip",
                    "before_sha256": "a",
                    "after_sha256": "a",
                    "unchanged": True,
                },
                "autoruns": {
                    "csv_member": "autoruns.csv",
                    "row_count": 2,
                    "enabled_count": 1,
                    "category_counts": [{"category": "Services", "count": 1}],
                    "signer_counts": [{"signer_state": "missing", "count": 1}],
                    "high_signal_candidates": [
                        {
                            "entry": "coreupdater",
                            "category": "Services",
                            "image_path": r"c:\windows\system32\coreupdater.exe",
                            "high_signal_reasons": "unsigned_persistence_binary",
                        }
                    ],
                    "review_candidates": [
                        {
                            "entry": "coreupdater",
                            "category": "Services",
                            "signer": "",
                            "image_path": r"c:\windows\system32\coreupdater.exe",
                            "reasons": "unverified_or_missing_signer",
                        }
                    ],
                },
                "observations": ["Review the candidate."],
            }
        )
        self.assertIn("coreupdater", report)
        self.assertIn("Services", report)
        self.assertIn("High-Signal", report)
