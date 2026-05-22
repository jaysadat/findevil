import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.run_manifest import verify_run_manifest, write_run_manifest


class RunManifestTests(TestCase):
    def test_signed_manifest_verifies_bundle_files(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "execution-log.json").write_text('{"status": "ok"}', encoding="utf-8")
            lane = output / "pcap"
            lane.mkdir()
            (lane / "summary.json").write_text('{"evidence": "preserved"}', encoding="utf-8")

            result = write_run_manifest(
                output,
                workflow="case_plan",
                case_id="sample",
                case_name="Sample",
                workflow_status="ok",
                generated_at="2026-05-22T00:00:00Z",
                signing_key=b"local-export-key",
                signing_key_id="operator-1",
            )
            verification = verify_run_manifest(
                Path(result["manifest"]),
                signing_key=b"local-export-key",
            )
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))

        self.assertTrue(result["signed"])
        self.assertEqual(result["file_count"], 2)
        self.assertEqual(manifest["bundle_root"], ".")
        self.assertEqual(manifest["signature"]["key_id"], "operator-1")
        self.assertTrue(verification["passed"])
        self.assertEqual(verification["signature"]["status"], "verified")

    def test_signed_manifest_requires_key_and_detects_file_drift(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory)
            report = output / "execution-report.md"
            report.write_text("preserved\n", encoding="utf-8")
            result = write_run_manifest(
                output,
                workflow="case_plan",
                case_id="sample",
                case_name="Sample",
                workflow_status="ok",
                generated_at="2026-05-22T00:00:00Z",
                signing_key=b"local-export-key",
            )

            missing_key = verify_run_manifest(Path(result["manifest"]))
            report.write_text("changed\n", encoding="utf-8")
            drifted = verify_run_manifest(
                Path(result["manifest"]),
                signing_key=b"local-export-key",
            )

        self.assertFalse(missing_key["passed"])
        self.assertEqual(missing_key["signature"]["status"], "key_required")
        self.assertFalse(drifted["passed"])
        self.assertFalse(drifted["files_passed"])
        self.assertEqual(drifted["files"][0]["status"], "digest_mismatch")

    def test_malformed_signature_fails_verification_without_crashing(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "execution-log.json").write_text('{"status": "ok"}', encoding="utf-8")
            result = write_run_manifest(
                output,
                workflow="case_plan",
                case_id="sample",
                case_name="Sample",
                workflow_status="ok",
                generated_at="2026-05-22T00:00:00Z",
            )
            manifest_path = Path(result["manifest"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["signature"] = "tampered"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            verification = verify_run_manifest(manifest_path, signing_key=b"key")

        self.assertFalse(verification["passed"])
        self.assertEqual(verification["signature"]["status"], "malformed")
