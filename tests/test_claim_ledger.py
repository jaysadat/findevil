from unittest import TestCase

from findevil_sift.reports import build_claim_ledger, render_claim_ledger_report


class ClaimLedgerTests(TestCase):
    def test_ledger_tracks_claim_status_and_sources(self) -> None:
        ledger = build_claim_ledger(
            {
                "inputs": {
                    "autoruns_summary": "autoruns.json",
                    "registry_summary": "registry.json",
                },
                "links": [
                    {
                        "type": "persistence_corroboration",
                        "confidence": "corroborated_pivot",
                        "support": ["Autoruns", "Registry"],
                        "value": [{"entry": "coreupdater"}],
                    }
                ],
            }
        )
        report = render_claim_ledger_report(ledger)

        self.assertEqual(ledger["claims"][0]["status"], "corroborated_pivot")
        self.assertEqual(ledger["claims"][0]["source_summaries"], ["autoruns.json", "registry.json"])
        self.assertIn("Candidate and volatile pivots are not confirmed findings.", report)

    def test_ledger_builds_mixed_link_types_without_cross_type_statement_eval(self) -> None:
        ledger = build_claim_ledger(
            {
                "inputs": {"pcap_summary": "pcap.json", "disk_summary": "disk.json"},
                "links": [
                    {
                        "type": "domain_hint_match",
                        "confidence": "supported",
                        "support": ["PCAP", "Disk"],
                        "value": "c137.local",
                    }
                ],
            }
        )

        self.assertIn("c137.local", ledger["claims"][0]["statement"])
