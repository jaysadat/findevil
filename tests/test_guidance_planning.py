import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.guidance_planning import (
    PLANNING_SCHEMA,
    build_guidance_plan_draft,
    draft_guidance_plan,
)
from findevil_sift.knowledge import EVIDENCE_BOUNDARY, catalog_knowledge, index_knowledge


class GuidancePlanningTests(TestCase):
    def test_builds_review_only_draft_with_lanes_and_memory_terms(self) -> None:
        draft = build_guidance_plan_draft(
            index={"knowledge_id": "guidance"},
            index_path=Path("knowledge/indexes/sample/knowledge-index.json"),
            case_id="acme",
            case_name="ACME",
            case_context="Need memory review for suspect.exe and pcap network pivots.",
            hits=[
                {
                    "relative_path": "memory.md",
                    "location": "document",
                    "chunk_id": "abc-0001",
                    "source_sha256": "a" * 64,
                    "score": 4,
                    "matched_terms": {"memory": 1},
                    "text": "Use Volatility pslist and psscan for process review.",
                }
            ],
        )

        lanes = {item["lane"] for item in draft["suggested_lanes"]}
        self.assertEqual(draft["schema"], PLANNING_SCHEMA)
        self.assertEqual(draft["boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(draft["status"], "needs_review")
        self.assertIn("memory", lanes)
        self.assertIn("pcap", lanes)
        self.assertIn("suspect.exe", draft["suggested_memory_terms"])
        self.assertIn("must not be treated as a case plan", draft["review_requirements"][0])

    def test_memory_terms_come_from_case_context_not_reference_text(self) -> None:
        draft = build_guidance_plan_draft(
            index={"knowledge_id": "guidance"},
            index_path=Path("knowledge/indexes/sample/knowledge-index.json"),
            case_id="acme",
            case_name="ACME",
            case_context="Need memory review for suspect.exe.",
            hits=[
                {
                    "relative_path": "memory.md",
                    "location": "document",
                    "chunk_id": "abc-0001",
                    "source_sha256": "a" * 64,
                    "score": 4,
                    "matched_terms": {"memory": 1},
                    "text": "Memory tools may require pagefile.sys and swapfile.sys.",
                }
            ],
        )

        self.assertEqual(draft["suggested_memory_terms"], ["suspect.exe"])

    def test_draft_guidance_plan_writes_review_artifacts_from_index(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "references"
            root.mkdir()
            (root / "memory.md").write_text(
                "Memory forensics can review suspect.exe with Volatility process plugins.",
                encoding="utf-8",
            )
            manifest_path = Path(directory) / "knowledge.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "knowledge_id": "guidance",
                        "roots": [
                            {
                                "label": "local",
                                "path": str(root),
                                "include": ["**/*.md"],
                                "allowed_suffixes": [".md"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            catalog = catalog_knowledge(manifest_path, Path(directory) / "catalog")
            index = index_knowledge(Path(catalog["summary"]), Path(directory) / "index")

            result = draft_guidance_plan(
                index_path=Path(index["summary"]),
                case_id="acme",
                case_name="ACME",
                case_context="Investigate memory process suspect.exe",
                output_dir=Path(directory) / "draft",
            )
            draft = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "needs_review")
        self.assertGreaterEqual(result["suggested_lane_count"], 1)
        self.assertEqual(draft["schema"], PLANNING_SCHEMA)
        self.assertIn("memory", {item["lane"] for item in draft["suggested_lanes"]})
