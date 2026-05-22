import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.knowledge import (
    EVIDENCE_BOUNDARY,
    catalog_knowledge,
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
