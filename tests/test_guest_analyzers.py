import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from findevil_sift.guest import (
    autoruns_triage_guest,
    case_inventory_guest,
    disk_triage_guest,
    memory_triage_guest,
    pcap_triage_guest,
    registry_triage_guest,
    userassist_triage_guest,
)


class GuestEvidencePlacementTests(TestCase):
    def test_lane_validators_reject_evidence_outside_cases(self) -> None:
        validators = [
            ("capture.pcap", pcap_triage_guest.validate_evidence_path, "PCAP evidence"),
            ("disk.E01", disk_triage_guest.validate_image_path, "disk evidence"),
            ("autoruns.zip", autoruns_triage_guest.validate_zip_path, "Autoruns evidence"),
            ("protected.zip", registry_triage_guest.validate_zip_path, "Protected-files evidence"),
            ("memory.mem", memory_triage_guest.validate_memory_path, "memory evidence"),
            ("userassist.zip", userassist_triage_guest.validate_zip_path, "UserAssist evidence"),
        ]

        with TemporaryDirectory() as directory:
            for name, validator, label in validators:
                evidence_path = Path(directory) / name
                evidence_path.write_bytes(b"fixture")

                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, f"{label} must live below /cases/"):
                        validator(evidence_path)

    def test_case_inventory_rejects_root_outside_cases(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "case root must live below /cases/"):
                case_inventory_guest.validate_case_root(Path(directory))


class PcapGuestIntegrityTests(TestCase):
    def test_summary_marks_evidence_hash_drift(self) -> None:
        with TemporaryDirectory() as directory:
            output_dir = Path(directory) / "output"
            fake_path = Path("/cases/example/capture.pcap")
            before = {"sha256": "before", "size_bytes": 7}
            after = {"sha256": "after", "size_bytes": 7}

            with (
                patch.object(pcap_triage_guest, "validate_evidence_path", return_value=fake_path),
                patch.object(pcap_triage_guest, "hash_file", side_effect=[before, after]),
                patch.object(
                    pcap_triage_guest,
                    "run_allowed",
                    side_effect=[{"stdout": "", "stderr": ""}, {"stdout": "", "stderr": ""}],
                ),
                patch.object(pcap_triage_guest, "log_inventory", return_value=[]),
                patch.object(pcap_triage_guest, "summarize_network", return_value={}),
                patch.object(pcap_triage_guest, "observations", return_value=[]),
                patch.object(pcap_triage_guest, "zip_logs"),
                patch(
                    "sys.argv",
                    [
                        "pcap_triage_guest.py",
                        "--pcap",
                        str(fake_path),
                        "--output-dir",
                        str(output_dir),
                    ],
                ),
            ):
                self.assertEqual(pcap_triage_guest.main(), 0)

            summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))

        self.assertEqual(summary["evidence"]["before_sha256"], "before")
        self.assertEqual(summary["evidence"]["after_sha256"], "after")
        self.assertFalse(summary["evidence"]["unchanged"])
