import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from findevil_sift.correlate import correlate_case_summaries, render_case_correlation


class CorrelateTests(TestCase):
    def test_domain_hints_link_pcap_and_disk_summaries(self) -> None:
        pcap = {
            "evidence": {"unchanged": True},
            "network": {
                "dns_domain_hints": ["c137.local"],
                "top_responder_services": [
                    {
                        "responder": "10.0.0.10",
                        "port": "3389",
                        "proto": "tcp",
                        "service": "ssl",
                        "connections": 8,
                    }
                ],
            },
        }
        disk = {
            "evidence": {"unchanged": True},
            "filesystem": {
                "domain_hints": ["c137.local"],
                "artifact_counts": [{"artifact": "ntds_database", "count": 1}],
            },
        }
        autoruns = {
            "evidence": {"unchanged": True},
            "autoruns": {
                "high_signal_candidates": [
                    {
                        "entry": "coreupdate",
                        "category": "Logon",
                        "image_path": r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                        "high_signal_reasons": "payload_like_script_launch",
                    }
                ]
            },
        }
        registry = {
            "evidence": {"unchanged": True},
            "registry": {
                "high_signal_candidates": [
                    {
                        "entry": "coreupdate",
                        "kind": "run_value",
                        "value": "powershell -nop",
                        "high_signal_reasons": "payload_like_run_command",
                    }
                ]
            },
        }
        memory = {
            "evidence": {"unchanged": True},
            "memory": {
                "hit_counts": [
                    {"term": "coreupdater", "count": 24},
                    {"term": "203.78.103.109", "count": 1},
                ]
            },
        }
        userassist = {
            "evidence": {"unchanged": True},
            "userassist": {
                "execution_entries": [
                    {
                        "profile": "Administrator",
                        "timestamp": "2020-09-19 03:56:37Z",
                        "entry": r"{GUID}\coreupdate.exe",
                        "executable_name": "coreupdate.exe",
                    }
                ]
            },
        }

        with TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "pcap.json"
            disk_path = Path(directory) / "disk.json"
            autoruns_path = Path(directory) / "autoruns.json"
            registry_path = Path(directory) / "registry.json"
            userassist_path = Path(directory) / "userassist.json"
            memory_path = Path(directory) / "memory.json"
            pcap_path.write_text(json.dumps(pcap), encoding="utf-8")
            disk_path.write_text(json.dumps(disk), encoding="utf-8")
            autoruns_path.write_text(json.dumps(autoruns), encoding="utf-8")
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            userassist_path.write_text(json.dumps(userassist), encoding="utf-8")
            memory_path.write_text(json.dumps(memory), encoding="utf-8")

            correlation = correlate_case_summaries(
                pcap_path,
                disk_path,
                autoruns_path,
                registry_path,
                userassist_path,
                memory_path,
            )

        report = render_case_correlation(correlation)
        self.assertEqual(correlation["links"][0]["value"], "c137.local")
        self.assertIn("c137.local", report)
        self.assertIn("10.0.0.10", report)
        self.assertIn("coreupdate", report)
        self.assertIn("coreupdater", report)
        self.assertIn("UserAssist", report)
        self.assertIn("corroborate", report.lower())
