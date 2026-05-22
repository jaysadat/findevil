from unittest import TestCase

from findevil_sift.reports import render_disk_report


class DiskReportTests(TestCase):
    def test_report_surfaces_segments_partitions_and_artifacts(self) -> None:
        report = render_disk_report(
            {
                "evidence": {
                    "primary_path": "/cases/disk.E01",
                    "unchanged": True,
                    "segments": [
                        {
                            "path": "/cases/disk.E01",
                            "size_bytes": 5,
                            "sha256": "abc",
                            "unchanged": True,
                        }
                    ],
                },
                "disk": {
                    "ewf_metadata": {
                        "case_number": "case",
                        "description": "dc",
                        "evidence_number": "ev",
                        "is_corrupted": "no",
                    },
                    "partitions": [
                        {
                            "slot": "003",
                            "start": "10",
                            "end": "20",
                            "length": "11",
                            "description": "NTFS",
                        }
                    ],
                },
                "filesystem": {
                    "offset_sectors": "10",
                    "metadata": {"file_system_type": "NTFS", "volume_serial_number": "serial"},
                    "artifact_counts": [{"artifact": "event_logs", "count": 2}],
                    "artifact_samples": {"event_logs": ["Windows/System32/winevt/Logs/System.evtx"]},
                },
                "observations": ["Disk pivots are available."],
            }
        )

        self.assertIn("disk.E01", report)
        self.assertIn("event_logs", report)
        self.assertIn("Windows/System32/winevt/Logs/System.evtx", report)
