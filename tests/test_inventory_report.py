from unittest import TestCase

from findevil_sift.reports import render_case_inventory_report


class CaseInventoryReportTests(TestCase):
    def test_report_surfaces_candidate_artifacts(self) -> None:
        report = render_case_inventory_report(
            {
                "generated_at": "2026-05-22T00:00:00Z",
                "case_root": "/cases/acme",
                "scan": {"scanned_files": 3, "candidate_count": 1, "truncated": False},
                "candidate_counts": [{"lane": "pcap", "count": 1}],
                "candidates": [
                    {
                        "lane": "pcap",
                        "guest_path": "/cases/acme/network.pcap",
                        "size_bytes": 99,
                        "reason": "pcap_suffix",
                    }
                ],
                "observations": ["Review candidates."],
            }
        )

        self.assertIn("Case Inventory", report)
        self.assertIn("/cases/acme/network.pcap", report)
        self.assertIn("Review candidates.", report)
