from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .case_plans import SUPPORTED_LANES
from .knowledge import EVIDENCE_BOUNDARY, guidance_hits, validate_index_for_query
from .config import enforce_knowledge_index_policy

PLANNING_SCHEMA = "findevil.guidance_plan_draft.v1"
MAX_PLANNING_HITS = 8
LANE_KEYWORDS = {
    "pcap": {"pcap", "zeek", "network", "dns", "http", "ssl", "tls", "packet"},
    "disk": {"disk", "filesystem", "file system", "fls", "mmls", "timeline", "e01"},
    "autoruns": {"autoruns", "startup", "persistence", "run key", "service"},
    "registry": {"registry", "hive", "reg", "run key", "services"},
    "userassist": {"userassist", "ntuser", "execution", "launched"},
    "memory": {"memory", "volatility", "memprocfs", "process", "injection", "pslist", "psscan"},
}


def draft_guidance_plan(
    *,
    index_path: Path,
    case_id: str,
    case_name: str,
    case_context: str,
    output_dir: Path,
    limit: int = 5,
) -> dict[str, str | int]:
    if limit < 1 or limit > MAX_PLANNING_HITS:
        raise ValueError(f"guidance plan limit must be between 1 and {MAX_PLANNING_HITS}")
    context = case_context.strip()
    if not context:
        raise ValueError("case context is required for guidance planning")
    resolved_index = index_path.resolve(strict=True)
    enforce_knowledge_index_policy(resolved_index)
    index = json.loads(resolved_index.read_text(encoding="utf-8"))
    validate_index_for_query(index)
    hits = guidance_hits(index, context, limit)
    draft = build_guidance_plan_draft(
        index=index,
        index_path=resolved_index,
        case_id=case_id,
        case_name=case_name,
        case_context=context,
        hits=hits,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "guidance-plan-draft.json"
    report_path = output_dir / "guidance-plan-draft.md"
    summary_path.write_text(json.dumps(draft, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_guidance_plan_draft(draft), encoding="utf-8")
    return {
        "status": "needs_review",
        "summary": str(summary_path),
        "report": str(report_path),
        "suggested_lane_count": len(draft["suggested_lanes"]),
        "next_action_count": len(draft["next_actions"]),
        "hit_count": len(hits),
    }


def build_guidance_plan_draft(
    *,
    index: dict[str, Any],
    index_path: Path,
    case_id: str,
    case_name: str,
    case_context: str,
    hits: list[dict[str, Any]],
) -> dict[str, Any]:
    lane_scores = score_lanes(case_context, hits)
    suggested_lanes = [
        {
            "lane": lane,
            "review_status": "suggested_from_guidance",
            "reason": reason_for_lane(lane, score, hits),
        }
        for lane, score in sorted(lane_scores.items(), key=lambda item: (-item[1], item[0]))
        if score > 0
    ]
    memory_terms = suggested_memory_terms(case_context) if lane_scores.get("memory", 0) > 0 else []
    return {
        "schema": PLANNING_SCHEMA,
        "generated_at": utc_now(),
        "status": "needs_review",
        "case_id": case_id,
        "case_name": case_name,
        "case_context": case_context,
        "knowledge_id": index["knowledge_id"],
        "index_path": str(index_path),
        "boundary": EVIDENCE_BOUNDARY,
        "review_requirements": [
            "This artifact is a draft planning aid and must not be treated as a case plan.",
            "Review evidence inventory before adding, removing, or running lanes.",
            "Memory terms are guidance pivots only; replace them with case-specific evidence pivots before triage.",
            "Do not promote guidance text to findings without preserved case evidence.",
        ],
        "suggested_lanes": suggested_lanes,
        "suggested_memory_terms": memory_terms,
        "next_actions": next_actions(suggested_lanes, memory_terms),
        "guidance_hits": [
            {
                "relative_path": hit["relative_path"],
                "location": hit["location"],
                "chunk_id": hit["chunk_id"],
                "source_sha256": hit["source_sha256"],
                "score": hit["score"],
                "matched_terms": hit["matched_terms"],
            }
            for hit in hits
        ],
    }


def score_lanes(case_context: str, hits: list[dict[str, Any]]) -> dict[str, int]:
    corpus = " ".join([case_context, *(hit["text"] for hit in hits)]).lower()
    scores = {}
    for lane in SUPPORTED_LANES:
        scores[lane] = sum(1 for keyword in LANE_KEYWORDS[lane] if keyword in corpus)
    return scores


def reason_for_lane(lane: str, score: int, hits: list[dict[str, Any]]) -> str:
    sources = sorted({hit["relative_path"] for hit in hits if any(keyword in hit["text"].lower() for keyword in LANE_KEYWORDS[lane])})
    if sources:
        return f"Matched {score} lane keyword(s) in case context or guidance hits from {', '.join(sources[:3])}."
    return f"Matched {score} lane keyword(s) in case context."


def suggested_memory_terms(case_context: str) -> list[str]:
    candidates = set()
    for value in re.findall(r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|sys)\b", case_context, flags=re.IGNORECASE):
        candidates.add(value.lower())
    for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", case_context):
        candidates.add(value)
    return sorted(candidates)[:8]


def next_actions(suggested_lanes: list[dict[str, Any]], memory_terms: list[str]) -> list[str]:
    actions = ["Review discovered evidence inventory before creating or changing a case plan."]
    lane_names = {item["lane"] for item in suggested_lanes}
    if lane_names:
        actions.append(f"Review whether these lanes belong in scope: {', '.join(sorted(lane_names))}.")
    if "memory" in lane_names and memory_terms:
        actions.append("Review suggested memory terms and keep only pivots observed in case evidence.")
    if "memory" in lane_names and not memory_terms:
        actions.append("Supply explicit case-specific memory search terms before running memory triage.")
    actions.append("Run validate-case-plan after any analyst-authored plan update.")
    return actions


def render_guidance_plan_draft(draft: dict[str, Any]) -> str:
    lanes = "\n".join(
        f"- `{item['lane']}`: {item['reason']}"
        for item in draft["suggested_lanes"]
    )
    terms = "\n".join(f"- `{term}`" for term in draft["suggested_memory_terms"])
    actions = "\n".join(f"- {item}" for item in draft["next_actions"])
    hits = "\n".join(
        f"- `{hit['relative_path']}` {hit['location']} (`{hit['chunk_id']}`, score {hit['score']})"
        for hit in draft["guidance_hits"]
    )
    reviews = "\n".join(f"- {item}" for item in draft["review_requirements"])
    return f"""# Find Evil Guidance Plan Draft

Generated: {draft["generated_at"]}

## Boundary

{draft["boundary"]}

## Review Required

{reviews}

## Case Context

- Case ID: `{draft["case_id"]}`
- Case name: `{draft["case_name"]}`
- Status: `{draft["status"]}`

## Suggested Lanes

{lanes or "- No lanes were suggested from the provided context and guidance hits."}

## Suggested Memory Terms

{terms or "- No memory terms were suggested."}

## Next Actions

{actions}

## Guidance Sources

{hits or "- No guidance hits were available."}
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
