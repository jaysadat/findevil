from unittest import TestCase

from findevil_sift.reports import render_memory_report


class MemoryReportTests(TestCase):
    def test_report_surfaces_memory_string_hits(self) -> None:
        report = render_memory_report(
            {
                "evidence": {
                    "path": "/cases/memory.mem",
                    "before_sha256": "a",
                    "after_sha256": "a",
                    "unchanged": True,
                },
                "memory": {
                    "hit_counts": [{"term": "coreupdater", "count": 2}],
                    "hit_samples": {
                        "coreupdater": [{"encoding": "utf16le", "line": "coreupdater.exe"}]
                    },
                },
                "observations": ["Review memory string hits."],
            }
        )
        self.assertIn("coreupdater", report)
        self.assertIn("Memory String", report)
