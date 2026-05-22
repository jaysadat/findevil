from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROMOTABLE_STATUSES = {"supported", "corroborated_pivot"}


def review_claim_promotion(ledger: dict[str, Any], *, max_iterations: int = 2) -> dict[str, Any]:
    if max_iterations < 1:
        raise ValueError("max_iterations must be at least 1")
    claims = ledger.get("claims", [])
    iterations = []
    blocked: list[dict[str, Any]] = []
    promoted: list[dict[str, Any]] = []
    changed = True
    for iteration in range(1, max_iterations + 1):
        proposed_promoted = [claim for claim in claims if claim["status"] in PROMOTABLE_STATUSES]
        proposed_blocked = [claim for claim in claims if claim["status"] not in PROMOTABLE_STATUSES]
        next_blocked = [
            {
                "claim_id": claim["claim_id"],
                "type": claim["type"],
                "status": claim["status"],
                "reason": block_reason(claim["status"]),
            }
            for claim in proposed_blocked
        ]
        next_promoted = [
            {
                "claim_id": claim["claim_id"],
                "type": claim["type"],
                "status": claim["status"],
                "statement": claim["statement"],
            }
            for claim in proposed_promoted
        ]
        changed = next_blocked != blocked or next_promoted != promoted
        iterations.append(
            {
                "iteration": iteration,
                "changed": changed,
                "promoted_claim_ids": [claim["claim_id"] for claim in next_promoted],
                "blocked_claim_ids": [claim["claim_id"] for claim in next_blocked],
                "decision": (
                    "Applied promotion status gate."
                    if changed
                    else "Promotion set stable; review loop stopped."
                ),
            }
        )
        blocked = next_blocked
        promoted = next_promoted
        if not changed:
            break
    return {
        "generated_at": utc_now(),
        "status": "stable" if iterations and not iterations[-1]["changed"] else "max_iterations_reached",
        "max_iterations": max_iterations,
        "promotable_statuses": sorted(PROMOTABLE_STATUSES),
        "promoted_claims": promoted,
        "blocked_claims": blocked,
        "iterations": iterations,
        "boundary": (
            "The review loop promotes only supported or corroborated claim classes. "
            "Candidate and volatile pivots remain analyst-review material."
        ),
    }


def block_reason(status: str) -> str:
    return {
        "candidate": "Candidate pivot lacks cross-source corroboration required for promotion.",
        "volatile_pivot": "Volatile string pivot is useful follow-up but not promoted as a finding.",
    }.get(status, f"Claim status {status} is not promotable.")


def render_quality_review(review: dict[str, Any]) -> str:
    promoted = "\n".join(
        f"- `{claim['claim_id']}` `{claim['status']}`: {claim['statement']}"
        for claim in review["promoted_claims"]
    )
    blocked = "\n".join(
        f"- `{claim['claim_id']}` `{claim['status']}`: {claim['reason']}"
        for claim in review["blocked_claims"]
    )
    iterations = "\n".join(
        f"| {item['iteration']} | {str(item['changed']).lower()} | "
        f"{', '.join(item['promoted_claim_ids']) or 'None'} | "
        f"{', '.join(item['blocked_claim_ids']) or 'None'} | {item['decision']} |"
        for item in review["iterations"]
    )
    return f"""# Find Evil Quality Review

Generated: {review["generated_at"]}

## Review Boundary

{review["boundary"]}

## Loop Status

- Status: `{review["status"]}`
- Maximum iterations: `{review["max_iterations"]}`
- Promotable statuses: `{", ".join(review["promotable_statuses"])}`

## Iteration Trace

| Iteration | Changed | Promoted Claims | Blocked Claims | Decision |
| --- | --- | --- | --- | --- |
{iterations}

## Promoted Claims

{promoted or "- No claims met the promotion gate."}

## Blocked Claims

{blocked or "- No claims were blocked by the promotion gate."}
"""


def write_quality_review(ledger: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    review = review_claim_promotion(ledger)
    summary_path = output_dir / "quality-review.json"
    report_path = output_dir / "quality-review.md"
    summary_path.write_text(json.dumps(review, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_quality_review(review), encoding="utf-8")
    return {"summary": str(summary_path), "report": str(report_path)}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
