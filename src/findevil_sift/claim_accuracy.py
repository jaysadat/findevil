from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def evaluate_claim_review(quality_review: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    promoted = quality_review.get("promoted_claims", [])
    blocked = quality_review.get("blocked_claims", [])
    promoted_types = sorted({claim["type"] for claim in promoted})
    blocked_types = sorted({claim["type"] for claim in blocked})
    expected_promoted = sorted(set(manifest.get("expected_promoted_claim_types", [])))
    expected_blocked = sorted(set(manifest.get("expected_blocked_claim_types", [])))
    forbidden_statuses = sorted(set(manifest.get("forbidden_promoted_statuses", [])))

    true_positive_types = sorted(set(promoted_types) & set(expected_promoted))
    false_positive_types = sorted(set(promoted_types) - set(expected_promoted))
    missed_types = sorted(set(expected_promoted) - set(promoted_types))
    rejected_unsupported_types = sorted(set(blocked_types) & set(expected_blocked))
    missing_rejections = sorted(set(expected_blocked) - set(blocked_types))
    unsafe_promotions = [
        {
            "claim_id": claim["claim_id"],
            "type": claim["type"],
            "status": claim["status"],
        }
        for claim in promoted
        if claim["status"] in forbidden_statuses
    ]
    return {
        "generated_at": utc_now(),
        "accuracy_id": manifest.get("accuracy_id", "unspecified"),
        "passed": not false_positive_types
        and not missed_types
        and not missing_rejections
        and not unsafe_promotions,
        "inputs": {
            "quality_status": quality_review.get("status", "unknown"),
            "manifest_description": manifest.get("description"),
        },
        "expected": {
            "promoted_claim_types": expected_promoted,
            "blocked_claim_types": expected_blocked,
            "forbidden_promoted_statuses": forbidden_statuses,
        },
        "observed": {
            "promoted_claim_types": promoted_types,
            "blocked_claim_types": blocked_types,
        },
        "score": {
            "true_positive_claim_types": len(true_positive_types),
            "false_positive_claim_types": len(false_positive_types),
            "missed_expected_claim_types": len(missed_types),
            "rejected_unsupported_claim_types": len(rejected_unsupported_types),
            "missing_expected_rejections": len(missing_rejections),
            "unsafe_promotions": len(unsafe_promotions),
        },
        "results": {
            "true_positive_claim_types": true_positive_types,
            "false_positive_claim_types": false_positive_types,
            "missed_expected_claim_types": missed_types,
            "rejected_unsupported_claim_types": rejected_unsupported_types,
            "missing_expected_rejections": missing_rejections,
            "unsafe_promotions": unsafe_promotions,
        },
        "boundary": (
            "This labeled review scores claim-promotion behavior against a case manifest. "
            "It does not turn pivots into analyst-approved forensic findings."
        ),
    }


def render_claim_accuracy_report(evaluation: dict[str, Any]) -> str:
    score_rows = _table_rows(
        [{"metric": metric, "count": count} for metric, count in evaluation["score"].items()],
        ("metric", "count"),
    )
    expected_rows = _table_rows(
        [
            {
                "set": "promoted claim types",
                "values": ", ".join(evaluation["expected"]["promoted_claim_types"]) or "None",
            },
            {
                "set": "blocked claim types",
                "values": ", ".join(evaluation["expected"]["blocked_claim_types"]) or "None",
            },
            {
                "set": "forbidden promoted statuses",
                "values": ", ".join(evaluation["expected"]["forbidden_promoted_statuses"]) or "None",
            },
        ],
        ("set", "values"),
    )
    observed_rows = _table_rows(
        [
            {
                "set": "promoted claim types",
                "values": ", ".join(evaluation["observed"]["promoted_claim_types"]) or "None",
            },
            {
                "set": "blocked claim types",
                "values": ", ".join(evaluation["observed"]["blocked_claim_types"]) or "None",
            },
        ],
        ("set", "values"),
    )
    result_rows = _table_rows(
        [
            {"result": name, "values": _compact(values)}
            for name, values in evaluation["results"].items()
        ],
        ("result", "values"),
    )
    return f"""# Find Evil Claim Accuracy Review

Generated: {evaluation["generated_at"]}

## Scope

- Accuracy ID: `{evaluation["accuracy_id"]}`
- Passed: `{str(evaluation["passed"]).lower()}`
- Quality review status: `{evaluation["inputs"]["quality_status"]}`
- Boundary: {evaluation["boundary"]}

## Expected Review Behavior

{expected_rows}

## Observed Review Behavior

{observed_rows}

## Score

{score_rows}

## Result Detail

{result_rows}
"""


def write_claim_accuracy(
    quality_review: dict[str, Any],
    manifest_path: Path,
    output_dir: Path,
) -> dict[str, str | bool]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    evaluation = evaluate_claim_review(quality_review, manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "claim-accuracy.json"
    report_path = output_dir / "claim-accuracy.md"
    summary_path.write_text(json.dumps(evaluation, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_claim_accuracy_report(evaluation), encoding="utf-8")
    return {
        "summary": str(summary_path),
        "report": str(report_path),
        "passed": evaluation["passed"],
    }


def _compact(values: Any) -> str:
    if not values:
        return "None"
    if isinstance(values, list):
        return ", ".join(
            f"{item['claim_id']}:{item['type']}:{item['status']}" if isinstance(item, dict) else str(item)
            for item in values
        )
    return str(values)


def _table_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> str:
    header = "| " + " | ".join(key.replace("_", " ").title() for key in keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    body = [
        "| " + " | ".join(str(row.get(key, "-")).replace("|", "\\|") for key in keys) + " |"
        for row in rows
    ]
    return "\n".join([header, separator, *body])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
