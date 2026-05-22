from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from findevil_sift.workflow import (
    lane_summary,
    memory_lane_requires_terms_review,
    render_execution_report,
    run_planned_lane_artifacts,
    trace_requires_review,
)


class WorkflowReportTests(TestCase):
    def test_report_renders_structured_events(self) -> None:
        report = render_execution_report(
            {
                "workflow": "case_plan",
                "case_id": "sample",
                "case_name": "Sample",
                "generated_at": "2026-05-21T00:00:00Z",
                "status": "ok",
                "max_attempts": 2,
                "events": [
                    {
                        "timestamp": "2026-05-21T00:00:01Z",
                        "event": "bounded_retry",
                        "status": "ok",
                        "details": {"lane": "pcap", "reason": "validation"},
                    }
                ],
            }
        )

        self.assertIn("bounded_retry", report)
        self.assertIn("Maximum attempts", report)

    def test_memory_lane_placeholder_requires_adjustment(self) -> None:
        self.assertTrue(memory_lane_requires_terms_review({"terms": ["pivot-to-review"]}))
        self.assertFalse(memory_lane_requires_terms_review({"terms": ["suspect.exe"]}))

    def test_needs_review_events_raise_workflow_review_flag(self) -> None:
        self.assertTrue(trace_requires_review({"events": [{"status": "needs_review"}]}))
        self.assertFalse(trace_requires_review({"events": [{"status": "ok"}]}))

    def test_failed_lane_artifact_records_adjustment_and_continues(self) -> None:
        trace = {"events": []}
        completed = {
            "triage": {"summary": "second-summary.json"},
            "validation": None,
            "passed": True,
        }

        with patch(
            "findevil_sift.workflow.run_planned_lane",
            side_effect=[RuntimeError("guest analyzer failed"), completed],
        ):
            output = run_planned_lane_artifacts(
                trace=trace,
                lane="pcap",
                lane_plan={"artifacts": [{"guest_path": "/cases/a.pcap"}, {"guest_path": "/cases/b.pcap"}]},
                plan_path=Path("case.json"),
                output_root=Path("artifacts"),
                config=object(),
                max_attempts=2,
            )

        self.assertEqual(output["artifact_count"], 2)
        self.assertFalse(output["passed"])
        self.assertEqual(output["artifacts"][0]["error"], "guest analyzer failed")
        self.assertEqual(output["artifacts"][1], completed)
        self.assertEqual([event["event"] for event in trace["events"]], ["lane_failed", "lane_adjusted"])
        self.assertIn("remaining artifacts", trace["events"][1]["details"]["decision"])

    def test_lane_summary_uses_completed_artifact_after_failed_sibling(self) -> None:
        summary = lane_summary(
            {
                "pcap": {
                    "artifacts": [
                        {"triage": None, "passed": False},
                        {"triage": {"summary": "second-summary.json"}, "passed": True},
                    ]
                }
            },
            "pcap",
        )

        self.assertEqual(summary, Path("second-summary.json"))
