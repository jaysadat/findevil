from unittest import TestCase

from findevil_sift.claim_accuracy import evaluate_claim_review, render_claim_accuracy_report


class ClaimAccuracyTests(TestCase):
    def test_review_scores_promotions_and_rejected_claims(self) -> None:
        evaluation = evaluate_claim_review(
            {
                "status": "stable",
                "promoted_claims": [
                    {
                        "claim_id": "claim-001",
                        "type": "domain_hint_match",
                        "status": "supported",
                    }
                ],
                "blocked_claims": [
                    {
                        "claim_id": "claim-002",
                        "type": "memory_string_pivot",
                        "status": "volatile_pivot",
                    }
                ],
            },
            {
                "accuracy_id": "fixture",
                "expected_promoted_claim_types": ["domain_hint_match"],
                "expected_blocked_claim_types": ["memory_string_pivot"],
                "forbidden_promoted_statuses": ["candidate", "volatile_pivot"],
            },
        )
        report = render_claim_accuracy_report(evaluation)

        self.assertTrue(evaluation["passed"])
        self.assertEqual(evaluation["score"]["true_positive_claim_types"], 1)
        self.assertEqual(evaluation["score"]["rejected_unsupported_claim_types"], 1)
        self.assertIn("Claim Accuracy Review", report)

    def test_review_fails_unsafe_candidate_promotion(self) -> None:
        evaluation = evaluate_claim_review(
            {
                "promoted_claims": [
                    {
                        "claim_id": "claim-009",
                        "type": "dc_network_pivot",
                        "status": "candidate",
                    }
                ],
                "blocked_claims": [],
            },
            {
                "expected_promoted_claim_types": [],
                "forbidden_promoted_statuses": ["candidate"],
            },
        )

        self.assertFalse(evaluation["passed"])
        self.assertEqual(evaluation["score"]["false_positive_claim_types"], 1)
        self.assertEqual(evaluation["score"]["unsafe_promotions"], 1)
