from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.audit import AuditRecord, hash_file
from findevil_sift.tools import hash_evidence


class HashFileTests(TestCase):
    def test_hash_file_records_sha256_and_size(self) -> None:
        with TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "sample.bin"
            evidence_path.write_bytes(b"find evil\n")

            digest = hash_file(evidence_path)

        self.assertEqual(digest.algorithm, "sha256")
        self.assertEqual(digest.size_bytes, 10)
        self.assertEqual(
            digest.digest,
            "9c3e1de22ded519d6fe47ccabcaef4cd0a319987dce5cbc2f31fa1cbf39e5a2f",
        )
        self.assertEqual(digest.path, str(evidence_path))


class AuditRecordTests(TestCase):
    def test_record_serializes_evidence_snapshots(self) -> None:
        with TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "sample.bin"
            evidence_path.write_bytes(b"find evil\n")
            digest = hash_file(evidence_path)

        timestamp = datetime(2026, 5, 21, 10, 30, tzinfo=timezone.utc)
        record = AuditRecord.create(
            tool_name="hash_evidence",
            status="ok",
            inputs={"path": digest.path},
            outputs={"digest": digest.digest},
            evidence_before=[digest],
            evidence_after=[digest],
            started_at=timestamp,
            finished_at=timestamp,
        )

        payload = record.to_dict()

        self.assertEqual(payload["tool_name"], "hash_evidence")
        self.assertEqual(payload["started_at"], "2026-05-21T10:30:00Z")
        self.assertEqual(payload["finished_at"], "2026-05-21T10:30:00Z")
        self.assertEqual(payload["evidence_before"][0]["digest"], digest.digest)
        self.assertEqual(payload["evidence_after"][0]["size_bytes"], 10)


class HashEvidenceToolTests(TestCase):
    def test_hash_evidence_emits_before_and_after_snapshots(self) -> None:
        with TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "sample.bin"
            evidence_path.write_bytes(b"find evil\n")

            record = hash_evidence(evidence_path)

        payload = record.to_dict()

        self.assertEqual(payload["tool_name"], "hash_evidence")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["outputs"]["size_bytes"], 10)
        self.assertEqual(
            payload["evidence_before"][0]["digest"],
            payload["evidence_after"][0]["digest"],
        )
