import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.benchmarks import (
    validate_autoruns_summary,
    validate_disk_summary,
    validate_pcap_summary,
    validate_memory_summary,
    validate_registry_summary,
    validate_userassist_summary,
)


class PcapBenchmarkTests(TestCase):
    def test_manifest_validates_integrity_logs_counts_and_pivots(self) -> None:
        summary = {
            "evidence": {"before_sha256": "abc", "unchanged": True},
            "zeek_logs": [{"name": "conn.log"}],
            "network": {
                "connection_count": 3,
                "private_http_destinations": [{"host": "pivot.test"}],
                "file_mime_types": [{"value": "application/x-dosexec"}],
                "executable_http_downloads": [
                    {
                        "source": "10.0.0.5",
                        "destination": "192.0.2.9",
                        "uri": "/payload.exe",
                    }
                ],
                "ssl_protocol_violations": [{"destination": "198.51.100.7"}],
            },
        }
        manifest = {
            "benchmark_id": "sample",
            "expected_sha256": "abc",
            "required_logs": ["conn.log"],
            "minimum_network_counts": {"connection_count": 2},
            "expected_private_http_hosts": ["pivot.test"],
            "expected_file_mime_types": ["application/x-dosexec"],
            "expected_http_executable_downloads": [
                {
                    "source": "10.0.0.5",
                    "destination": "192.0.2.9",
                    "uri": "/payload.exe",
                }
            ],
            "expected_ssl_violation_destinations": ["198.51.100.7"],
        }

        with TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            manifest_path = Path(directory) / "manifest.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = validate_pcap_summary(summary_path, manifest_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 8, "total_checks": 8})


class DiskBenchmarkTests(TestCase):
    def test_manifest_validates_disk_segments_and_artifact_counts(self) -> None:
        summary = {
            "evidence": {
                "segment_count": 1,
                "unchanged": True,
                "segments": [{"path": "/cases/disk.E01", "sha256": "abc"}],
            },
            "filesystem": {
                "offset_sectors": "10",
                "artifact_counts": [{"artifact": "event_logs", "count": 2}],
            },
            "disk": {"ewf_metadata": {"description": "dc"}},
        }
        manifest = {
            "benchmark_id": "disk-sample",
            "expected_segment_count": 1,
            "expected_offset_sectors": 10,
            "expected_segment_sha256": {"disk.E01": "abc"},
            "minimum_artifact_counts": {"event_logs": 1},
            "expected_ewf_metadata": {"description": "dc"},
        }

        with TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            manifest_path = Path(directory) / "manifest.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = validate_disk_summary(summary_path, manifest_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 6, "total_checks": 6})


class AutorunsBenchmarkTests(TestCase):
    def test_manifest_validates_high_signal_entries(self) -> None:
        summary = {
            "evidence": {"before_sha256": "abc", "unchanged": True},
            "autoruns": {
                "csv_member": "autoruns.csv",
                "row_count": 10,
                "enabled_count": 8,
                "high_signal_candidates": [{"entry": "coreupdate"}],
            },
        }
        manifest = {
            "benchmark_id": "autoruns-sample",
            "expected_sha256": "abc",
            "expected_csv_member": "autoruns.csv",
            "minimum_autoruns_counts": {"row_count": 10, "enabled_count": 8},
            "expected_high_signal_entries": ["coreupdate"],
        }

        with TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            manifest_path = Path(directory) / "manifest.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = validate_autoruns_summary(summary_path, manifest_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 6, "total_checks": 6})


class RegistryBenchmarkTests(TestCase):
    def test_manifest_validates_hives_and_high_signal_entries(self) -> None:
        summary = {
            "evidence": {"before_sha256": "abc", "unchanged": True},
            "registry": {
                "hive_members": ["Protected/software", "Protected/system"],
                "run_entry_count": 2,
                "service_entry_count": 20,
                "high_signal_candidates": [{"entry": "coreupdater"}],
                "decoded_payload_chains": [
                    {
                        "key_path": "key",
                        "value_name": "value",
                        "nested_script": {"indicators": ["VirtualAlloc"]},
                    }
                ],
            },
        }
        manifest = {
            "benchmark_id": "registry-sample",
            "expected_sha256": "abc",
            "required_hive_members": ["Protected/software", "Protected/system"],
            "minimum_registry_counts": {"run_entry_count": 2, "service_entry_count": 10},
            "expected_high_signal_entries": ["coreupdater"],
            "expected_decoded_payloads": {"key\\value": ["VirtualAlloc"]},
        }

        with TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            manifest_path = Path(directory) / "manifest.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = validate_registry_summary(summary_path, manifest_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 8, "total_checks": 8})


class MemoryBenchmarkTests(TestCase):
    def test_manifest_validates_memory_term_hits(self) -> None:
        summary = {
            "evidence": {"before_sha256": "abc", "unchanged": True},
            "memory": {"hit_counts": [{"term": "core", "count": 2}]},
        }
        manifest = {
            "benchmark_id": "memory-sample",
            "expected_sha256": "abc",
            "minimum_term_hits": {"core": 1},
        }

        with TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            manifest_path = Path(directory) / "manifest.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = validate_memory_summary(summary_path, manifest_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 3, "total_checks": 3})


class UserAssistBenchmarkTests(TestCase):
    def test_manifest_validates_exported_hives_and_execution_entries(self) -> None:
        summary = {
            "evidence": {"before_sha256": "abc", "unchanged": True},
            "userassist": {
                "hive_members": ["Users/Admin/NTUSER.DAT"],
                "profile_count": 1,
                "entry_count": 2,
                "execution_entries": [
                    {"executable_name": "powershell.exe"},
                    {"executable_name": "coreupdater.exe"},
                ],
            },
        }
        manifest = {
            "benchmark_id": "userassist-sample",
            "expected_sha256": "abc",
            "required_hive_members": ["Users/Admin/NTUSER.DAT"],
            "minimum_userassist_counts": {"profile_count": 1, "entry_count": 2},
            "expected_executable_names": ["powershell.exe", "coreupdater.exe"],
        }

        with TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            manifest_path = Path(directory) / "manifest.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = validate_userassist_summary(summary_path, manifest_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], {"passed_checks": 7, "total_checks": 7})
