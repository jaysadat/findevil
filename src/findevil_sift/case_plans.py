from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUPPORTED_LANES = ("pcap", "disk", "autoruns", "registry", "userassist", "memory")
DEFAULT_LANE_PATHS = {
    "pcap": "network/capture.pcap",
    "disk": "host01/image.E01",
    "autoruns": "host01/autoruns.zip",
    "registry": "host01/protected-files.zip",
    "userassist": "host01/protected-files.zip",
    "memory": "host01/memory.mem",
}
CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def load_and_validate_case_plan(plan_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = plan_path.resolve(strict=True)
    try:
        plan = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, validation_result(
            resolved,
            [
                check("json", False, "valid JSON object", f"{exc.msg} at line {exc.lineno}"),
            ],
        )
    return plan, validate_case_plan(plan, resolved)


def validate_case_plan(plan: Any, plan_path: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check("plan_object", isinstance(plan, dict), "JSON object", type(plan).__name__))
    if not isinstance(plan, dict):
        return validation_result(plan_path, checks)

    case_id = plan.get("case_id")
    case_name = plan.get("case_name")
    lanes = plan.get("lanes")
    checks.extend(
        [
            check(
                "case_id",
                isinstance(case_id, str) and bool(CASE_ID.fullmatch(case_id)),
                "non-empty identifier using letters, numbers, dot, underscore, or dash",
                case_id,
            ),
            check(
                "case_name",
                isinstance(case_name, str) and bool(case_name.strip()),
                "non-empty case display name",
                case_name,
            ),
            check(
                "lanes",
                isinstance(lanes, dict) and bool(lanes),
                "at least one lane object",
                sorted(lanes) if isinstance(lanes, dict) else type(lanes).__name__,
            ),
        ]
    )
    if isinstance(lanes, dict):
        for lane, lane_plan in lanes.items():
            checks.extend(validate_lane(plan_path, lane, lane_plan))

    profile = plan.get("scenario_profile")
    if profile is not None:
        checks.extend(validate_reference(plan_path, "scenario_profile", profile))
    accuracy_manifest = plan.get("claim_accuracy_manifest")
    if accuracy_manifest is not None:
        checks.extend(validate_reference(plan_path, "claim_accuracy_manifest", accuracy_manifest))
    return validation_result(plan_path, checks)


def validate_lane(plan_path: Path, lane: str, lane_plan: Any) -> list[dict[str, Any]]:
    checks = [
        check(
            f"lane:{lane}:supported",
            lane in SUPPORTED_LANES,
            f"one of {', '.join(SUPPORTED_LANES)}",
            lane,
        ),
        check(
            f"lane:{lane}:object",
            isinstance(lane_plan, dict),
            "lane configuration object",
            type(lane_plan).__name__,
        ),
    ]
    if lane not in SUPPORTED_LANES or not isinstance(lane_plan, dict):
        return checks

    artifacts = lane_artifacts(lane_plan)
    checks.append(
        check(
            f"lane:{lane}:artifacts",
            bool(artifacts),
            "one artifact object or a non-empty artifacts list",
            len(artifacts),
        )
    )
    for index, artifact in enumerate(artifacts, start=1):
        checks.extend(validate_artifact(plan_path, lane, artifact, index))
    return checks


def validate_artifact(
    plan_path: Path,
    lane: str,
    artifact: Any,
    index: int,
) -> list[dict[str, Any]]:
    prefix = f"lane:{lane}:artifact:{index}"
    checks = [
        check(
            f"{prefix}:object",
            isinstance(artifact, dict),
            "artifact configuration object",
            type(artifact).__name__,
        )
    ]
    if not isinstance(artifact, dict):
        return checks
    guest_path = artifact.get("guest_path")
    checks.append(
        check(
            f"{prefix}:guest_path",
            isinstance(guest_path, str) and guest_path.startswith("/cases/"),
            "guest evidence path below /cases/",
            guest_path,
        )
    )
    output_dir = artifact.get("output_dir")
    if output_dir is not None:
        output_path = Path(output_dir)
        checks.append(
            check(
                f"{prefix}:output_dir",
                isinstance(output_dir, str)
                and bool(output_dir.strip())
                and not output_path.is_absolute()
                and ".." not in output_path.parts,
                "relative output directory below the workflow output root",
                output_dir,
            )
        )
    if lane == "memory":
        terms = artifact.get("terms")
        checks.append(
            check(
                f"{prefix}:terms",
                isinstance(terms, list)
                and bool(terms)
                and all(isinstance(term, str) and bool(term.strip()) for term in terms),
                "non-empty list of explicit search terms",
                terms,
            )
        )
    benchmark = artifact.get("benchmark_manifest")
    if benchmark is not None:
        checks.extend(validate_reference(plan_path, f"{prefix}:benchmark_manifest", benchmark))
    return checks


def lane_artifacts(lane_plan: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = lane_plan.get("artifacts")
    if artifacts is not None:
        return artifacts if isinstance(artifacts, list) else []
    return [lane_plan]


def validate_reference(plan_path: Path, name: str, reference: Any) -> list[dict[str, Any]]:
    target = resolve_plan_reference(plan_path, reference) if isinstance(reference, str) else None
    return [
        check(
            name,
            isinstance(reference, str) and bool(reference.strip()),
            "non-empty file reference",
            reference,
        ),
        check(
            f"{name}:exists",
            bool(target and target.is_file()),
            "existing file resolved from the case plan",
            str(target) if target else None,
        ),
    ]


def build_case_plan_template(
    *,
    case_id: str,
    case_name: str,
    lanes: list[str],
) -> dict[str, Any]:
    invalid = sorted(set(lanes) - set(SUPPORTED_LANES))
    if invalid:
        raise ValueError(f"unsupported case-plan lanes: {', '.join(invalid)}")
    selected = lanes or ["pcap", "disk", "autoruns", "registry", "memory"]
    template_lanes: dict[str, dict[str, Any]] = {}
    for lane in selected:
        lane_plan: dict[str, Any] = {
            "guest_path": f"/cases/{case_id}/{DEFAULT_LANE_PATHS[lane]}",
        }
        if lane == "memory":
            lane_plan["terms"] = ["pivot-to-review"]
        template_lanes[lane] = lane_plan
    return {
        "case_id": case_id,
        "case_name": case_name,
        "description": "Edit guest evidence paths and optional validation controls for this case.",
        "lanes": template_lanes,
    }


def write_case_plan_template(
    output_path: Path,
    *,
    case_id: str,
    case_name: str,
    lanes: list[str],
) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(f"case plan already exists: {output_path}")
    template = build_case_plan_template(case_id=case_id, case_name=case_name, lanes=lanes)
    validation = validate_case_plan(template, output_path.resolve())
    if not validation["passed"]:
        raise ValueError(f"generated case plan did not validate: {validation}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    return {
        "status": "ok",
        "case_plan": str(output_path),
        "lanes": list(template["lanes"]),
        "validation": validation,
    }


def draft_case_plan_from_inventory(
    inventory: dict[str, Any],
    *,
    case_id: str,
    case_name: str,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {lane: [] for lane in SUPPORTED_LANES}
    for candidate in inventory.get("candidates", []):
        lane = candidate.get("lane")
        if lane in grouped and isinstance(candidate.get("guest_path"), str):
            grouped[lane].append(candidate)

    lanes: dict[str, dict[str, Any]] = {}
    selections: list[dict[str, Any]] = []
    for lane in SUPPORTED_LANES:
        choices = sorted(
            grouped[lane],
            key=lambda item: (len(item["guest_path"]), item["guest_path"].lower()),
        )
        if not choices:
            continue
        selected = choices[0]
        lane_artifact_configs = []
        for choice in choices:
            artifact: dict[str, Any] = {"guest_path": choice["guest_path"]}
            if lane == "memory":
                artifact["terms"] = ["pivot-to-review"]
            lane_artifact_configs.append(artifact)
        lanes[lane] = (
            lane_artifact_configs[0]
            if len(lane_artifact_configs) == 1
            else {"artifacts": lane_artifact_configs}
        )
        selections.append(
            {
                "lane": lane,
                "selected": selected["guest_path"],
                "candidate_count": len(choices),
                "review_required": len(choices) > 1 or lane == "memory",
            }
        )

    return {
        "case_id": case_id,
        "case_name": case_name,
        "description": "Drafted from SIFT case inventory. Review selected evidence paths before triage.",
        "lanes": lanes,
        "discovery": {
            "case_root": inventory.get("case_root"),
            "selection_policy": "shortest guest path, then lexical path",
            "selections": selections,
            "review_notes": [
                "Discovery candidates are heuristic evidence matches.",
                "Replace memory placeholder terms with analyst pivots before memory triage.",
            ],
        },
    }


def write_discovered_case_plan(
    output_path: Path,
    inventory: dict[str, Any],
    *,
    case_id: str,
    case_name: str,
) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(f"case plan already exists: {output_path}")
    plan = draft_case_plan_from_inventory(
        inventory,
        case_id=case_id,
        case_name=case_name,
    )
    validation = validate_case_plan(plan, output_path.resolve())
    if not validation["passed"]:
        raise ValueError(f"discovered case plan did not validate: {validation}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return {
        "case_plan": str(output_path),
        "lanes": list(plan["lanes"]),
        "validation": validation,
    }


def validation_result(plan_path: Path, checks: list[dict[str, Any]]) -> dict[str, Any]:
    passed_checks = sum(1 for item in checks if item["passed"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "plan_path": str(plan_path),
        "passed": passed_checks == len(checks),
        "score": {"passed_checks": passed_checks, "total_checks": len(checks)},
        "checks": checks,
    }


def check(name: str, passed: bool, expected: Any, observed: Any) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "expected": expected,
        "observed": observed,
    }


def resolve_plan_reference(plan_path: Path, reference: str) -> Path:
    path = Path(reference)
    return path if path.is_absolute() else (plan_path.parent / path).resolve()
