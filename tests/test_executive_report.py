from unittest import TestCase

from findevil_sift.reports import render_executive_report


class ExecutiveReportTests(TestCase):
    def test_report_surfaces_status_signals_and_boundary(self) -> None:
        report = render_executive_report(
            {
                "generated_at": "2026-05-22T00:00:00Z",
                "case_id": "acme",
                "case_name": "ACME",
                "workflow_status": "ok",
                "lane_summary": [
                    {"lane": "pcap", "artifacts": 2, "benchmarked": 0, "passed": True}
                ],
                "signals": ["Signal."],
                "caveats": [{"lane": "disk", "reason": "Hash caveat.", "decision": "Review."}],
                "next_actions": ["Review outputs."],
                "reporting_boundary": "Boundary.",
            }
        )

        self.assertIn("Executive Report", report)
        self.assertIn("Boundary.", report)
        self.assertIn("Signal.", report)
