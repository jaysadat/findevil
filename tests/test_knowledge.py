import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.knowledge import (
    EVIDENCE_BOUNDARY,
    catalog_knowledge,
    index_knowledge,
    query_knowledge,
    validate_knowledge_guidance,
    validate_knowledge_manifest,
)


class KnowledgeCatalogTests(TestCase):
    def test_manifest_rejects_unsupported_suffix(self) -> None:
        validation = validate_knowledge_manifest(
            {
                "knowledge_id": "guidance",
                "roots": [
                    {
                        "label": "bad",
                        "path": "references",
                        "allowed_suffixes": [".exe"],
                    }
                ],
            },
            Path("knowledge.json"),
        )

        failed = {item["name"] for item in validation["checks"] if not item["passed"]}
        self.assertIn("root:1:allowed_suffixes", failed)
        self.assertEqual(validation["boundary"], EVIDENCE_BOUNDARY)

    def test_catalog_hashes_local_reference_files_and_records_boundary(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "references"
            output = Path(directory) / "catalog"
            root.mkdir()
            (root / "guide.pdf").write_bytes(b"pdf guidance")
            (root / "notes.md").write_text("triage notes", encoding="utf-8")
            (root / "skip.exe").write_bytes(b"not guidance")
            manifest_path = Path(directory) / "knowledge.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "knowledge_id": "guidance",
                        "roots": [
                            {
                                "label": "local",
                                "path": str(root),
                                "include": ["**/*"],
                                "allowed_suffixes": [".pdf", ".md"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = catalog_knowledge(manifest_path, output)
            catalog = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))

        self.assertEqual(result["source_count"], 2)
        self.assertEqual(result["missing_root_count"], 0)
        self.assertEqual(catalog["boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual([item["relative_path"] for item in catalog["sources"]], ["guide.pdf", "notes.md"])
        self.assertEqual(len(catalog["sources"][0]["sha256"]), 64)

    def test_index_and_query_cataloged_guidance_preserve_boundary(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "references"
            catalog_output = Path(directory) / "catalog"
            index_output = Path(directory) / "index"
            query_output = Path(directory) / "query"
            root.mkdir()
            (root / "memory.md").write_text(
                "Use memory pivots to select Volatility plugins for process review.",
                encoding="utf-8",
            )
            (root / "disk.txt").write_text(
                "Disk triage should preserve filesystem timeline outputs.",
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
                                "include": ["**/*"],
                                "allowed_suffixes": [".md", ".txt"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            catalog = catalog_knowledge(manifest_path, catalog_output)
            index_result = index_knowledge(Path(catalog["summary"]), index_output)
            query_result = query_knowledge(
                Path(index_result["summary"]),
                "memory process",
                query_output,
            )
            guidance = json.loads(Path(query_result["summary"]).read_text(encoding="utf-8"))

        self.assertEqual(index_result["indexed_source_count"], 2)
        self.assertEqual(query_result["hit_count"], 1)
        self.assertEqual(guidance["boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(guidance["hits"][0]["relative_path"], "memory.md")
        self.assertIn("Volatility", guidance["hits"][0]["text"])

    def test_index_skips_source_when_catalog_hash_no_longer_matches(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "references"
            root.mkdir()
            source = root / "guide.md"
            source.write_text("approved text", encoding="utf-8")
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
            source.write_text("changed text", encoding="utf-8")
            index_result = index_knowledge(Path(catalog["summary"]), Path(directory) / "index")
            index = json.loads(Path(index_result["summary"]).read_text(encoding="utf-8"))

        self.assertEqual(index_result["status"], "partial")
        self.assertEqual(index_result["chunk_count"], 0)
        self.assertIn("SHA-256 changed", index["skipped_sources"][0]["reason"])

    def test_guidance_evaluation_scores_expected_source_hits(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "references"
            root.mkdir()
            (root / "memory.md").write_text(
                "Volatility memory process guidance for forensic review.",
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
            evaluation_path = Path(directory) / "evaluation.json"
            evaluation_path.write_text(
                json.dumps(
                    {
                        "evaluation_id": "memory-guidance",
                        "queries": [
                            {
                                "id": "memory-process",
                                "query": "memory volatility process",
                                "expected_relative_paths": ["memory.md"],
                                "limit": 3,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = validate_knowledge_guidance(Path(index["summary"]), evaluation_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 1, "total_checks": 1})
        self.assertEqual(result["cases"][0]["hit_relative_paths"], ["memory.md"])
