from unittest import TestCase

from findevil_sift.reports import render_pcap_report


class PcapReportTests(TestCase):
    def test_report_surfaces_integrity_and_pivots(self) -> None:
        report = render_pcap_report(
            {
                "capture": {
                    "file_type": "pcapng",
                    "number_of_packets": "42",
                    "capture_duration": "3 seconds",
                    "first_packet_time": "start",
                    "last_packet_time": "finish",
                },
                "evidence": {
                    "path": "/cases/sample.pcap",
                    "before_sha256": "before",
                    "after_sha256": "after",
                    "unchanged": True,
                },
                "network": {
                    "top_dns_queries": [{"value": "example.test", "count": 2}],
                    "top_http_hosts": [],
                    "executable_http_downloads": [
                        {
                            "ts": "1",
                            "source": "10.0.0.5",
                            "destination": "203.0.113.1",
                            "host": "203.0.113.1",
                            "uri": "/payload.exe",
                            "mime_types": "application/x-dosexec",
                        }
                    ],
                    "top_tls_server_names": [],
                    "ssl_protocol_violations": [
                        {
                            "ts": "2",
                            "source": "10.0.0.5",
                            "destination": "203.0.113.2",
                            "destination_port": "443",
                            "message": "invalid",
                        }
                    ],
                    "top_responder_services": [
                        {
                            "responder": "10.0.0.5",
                            "port": "443",
                            "proto": "tcp",
                            "service": "ssl",
                            "connections": 3,
                        }
                    ],
                    "notices": [],
                },
                "observations": ["Evidence remained unchanged."],
                "zeek_logs": [{"name": "conn.log", "records": 4, "size_bytes": 90}],
            }
        )

        self.assertIn("Evidence path: `/cases/sample.pcap`", report)
        self.assertIn("example.test", report)
        self.assertIn("10.0.0.5", report)
        self.assertIn("payload.exe", report)
        self.assertIn("conn.log", report)
