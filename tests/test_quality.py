from unittest import TestCase

from findevil_sift.quality import render_quality_review, review_claim_promotion


class QualityReviewTests(TestCase):
    def test_review_blocks_candidate_and_volatile_claims(self) -> None:
        review = review_claim_promotion(
            {
                "claims": [
                    {
                        "claim_id": "claim-001",
                        "type": "domain_hint_match",
                        "status": "supported",
                        "statement": "Supported.",
                    },
                    {
                        "claim_id": "claim-002",
                        "type": "dc_network_pivot",
                        "status": "candidate",
                        "statement": "Candidate.",
                    },
                    {
                        "claim_id": "claim-003",
                        "type": "memory_string_pivot",
                        "status": "volatile_pivot",
                        "statement": "Volatile.",
                    },
                ]
            }
        )
        report = render_quality_review(review)

        self.assertEqual([item["claim_id"] for item in review["promoted_claims"]], ["claim-001"])
        self.assertEqual(len(review["blocked_claims"]), 2)
        self.assertEqual(review["blocked_claims"][0]["type"], "dc_network_pivot")
        self.assertEqual(review["status"], "stable")
        self.assertIn("Iteration Trace", report)
