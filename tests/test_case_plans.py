import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.case_plans import (
    build_case_plan_template,
    draft_case_plan_from_inventory,
    load_and_validate_case_plan,
    validate_case_plan,
)


class CasePlanTests(TestCase):
    def test_template_is_valid_and_adds_memory_term_placeholder(self) -> None:
        plan = build_case_plan_template(
            case_id="acme-incident",
            case_name="ACME Incident",
            lanes=["pcap", "memory"],
        )

        result = validate_case_plan(plan, Path("cases/acme-incident.json"))

        self.assertTrue(result["passed"])
        self.assertEqual(plan["lanes"]["memory"]["terms"], ["pivot-to-review"])
        self.assertTrue(plan["lanes"]["pcap"]["guest_path"].startswith("/cases/"))

    def test_validation_rejects_unknown_lane_and_missing_memory_terms(self) -> None:
        result = validate_case_plan(
            {
                "case_id": "bad-case",
                "case_name": "Bad Case",
                "lanes": {
                    "memory": {"guest_path": "/cases/bad/memory.mem"},
                    "timeline": {"guest_path": "/cases/bad/timeline.json"},
                },
            },
            Path("cases/bad-case.json"),
        )

        failed = {item["name"] for item in result["checks"] if not item["passed"]}
        self.assertFalse(result["passed"])
        self.assertIn("lane:memory:artifact:1:terms", failed)
        self.assertIn("lane:timeline:supported", failed)

    def test_validation_resolves_optional_references_from_plan_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmarks" / "pcap.json"
            benchmark.parent.mkdir()
            benchmark.write_text("{}", encoding="utf-8")
            plan_path = root / "cases" / "case.json"
            plan_path.parent.mkdir()
            plan_path.write_text(
                json.dumps(
                    {
                        "case_id": "fixture",
                        "case_name": "Fixture",
                        "lanes": {
                            "pcap": {
                                "guest_path": "/cases/fixture/network.pcap",
                                "benchmark_manifest": "../benchmarks/pcap.json",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            _, result = load_and_validate_case_plan(plan_path)

        self.assertTrue(result["passed"])

    def test_inventory_draft_selects_candidates_and_marks_review(self) -> None:
        plan = draft_case_plan_from_inventory(
            {
                "case_root": "/cases/acme",
                "candidates": [
                    {"lane": "pcap", "guest_path": "/cases/acme/z/edge.pcap"},
                    {"lane": "pcap", "guest_path": "/cases/acme/a.pcap"},
                    {"lane": "memory", "guest_path": "/cases/acme/host/memory.mem"},
                ],
            },
            case_id="acme",
            case_name="ACME",
        )

        selections = {item["lane"]: item for item in plan["discovery"]["selections"]}
        self.assertEqual(plan["lanes"]["pcap"]["artifacts"][0]["guest_path"], "/cases/acme/a.pcap")
        self.assertEqual(plan["lanes"]["memory"]["terms"], ["pivot-to-review"])
        self.assertTrue(selections["pcap"]["review_required"])
        self.assertTrue(selections["memory"]["review_required"])

    def test_validation_accepts_multiple_lane_artifacts(self) -> None:
        result = validate_case_plan(
            {
                "case_id": "multi",
                "case_name": "Multi",
                "lanes": {
                    "autoruns": {
                        "artifacts": [
                            {"guest_path": "/cases/multi/host-a/autoruns.zip"},
                            {"guest_path": "/cases/multi/host-b/autoruns.zip"},
                        ]
                    }
                },
            },
            Path("cases/multi.json"),
        )

        self.assertTrue(result["passed"])

    def test_validation_rejects_path_escape_attempts(self) -> None:
        result = validate_case_plan(
            {
                "case_id": "escape",
                "case_name": "Escape",
                "lanes": {
                    "pcap": {
                        "guest_path": "/tmp/not-evidence.pcap",
                        "output_dir": "../outside",
                    }
                },
            },
            Path("cases/escape.json"),
        )

        failed = {item["name"] for item in result["checks"] if not item["passed"]}
        self.assertFalse(result["passed"])
        self.assertIn("lane:pcap:artifact:1:guest_path", failed)
        self.assertIn("lane:pcap:artifact:1:output_dir", failed)
