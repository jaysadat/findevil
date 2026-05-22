from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from .benchmarks import (
    validate_autoruns_summary,
    validate_disk_summary,
    validate_memory_summary,
    validate_pcap_summary,
    validate_registry_summary,
    validate_userassist_summary,
)
from .case_plans import lane_artifacts, load_and_validate_case_plan, resolve_plan_reference
from .claim_accuracy import write_claim_accuracy
from .correlate import correlate_case_summaries, write_case_correlation
from .scenario import align_case_profile, write_case_dossier
from .reports import write_claim_ledger, write_executive_report
from .quality import write_quality_review
from .vmware import (
    SiftVmConfig,
    triage_guest_autoruns,
    triage_guest_disk,
    triage_guest_memory,
    triage_guest_pcap,
    triage_guest_registry,
    triage_guest_userassist,
)

LaneRunner = Callable[[Path], dict[str, object]]
LaneValidator = Callable[[Path, Path], dict[str, Any]]


VALIDATORS: dict[str, LaneValidator] = {
    "pcap": validate_pcap_summary,
    "disk": validate_disk_summary,
    "autoruns": validate_autoruns_summary,
    "registry": validate_registry_summary,
    "userassist": validate_userassist_summary,
    "memory": validate_memory_summary,
}


def run_case_workflow(
    *,
    config: SiftVmConfig,
    case_plan_path: Path,
    output_root: Path,
    max_attempts: int = 2,
) -> dict[str, Any]:
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    output_root.mkdir(parents=True, exist_ok=True)
    plan_path = case_plan_path.resolve(strict=True)
    plan, plan_validation = load_and_validate_case_plan(plan_path)
    if not plan_validation["passed"]:
        raise ValueError(f"case plan validation failed: {plan_validation}")
    trace = {
        "workflow": "case_plan",
        "case_id": plan.get("case_id", plan_path.stem),
        "case_name": plan.get("case_name", plan_path.stem),
        "case_plan": str(plan_path),
        "generated_at": utc_now(),
        "max_attempts": max_attempts,
        "events": [],
    }
    add_event(
        trace,
        "workflow_started",
        "ok",
        {
            "output_root": str(output_root),
            "case_plan": str(plan_path),
            "configured_lanes": ", ".join(plan.get("lanes", {})),
        },
    )

    lane_outputs: dict[str, dict[str, Any]] = {}
    for lane, lane_plan in plan.get("lanes", {}).items():
        if lane == "memory" and memory_lane_requires_terms_review(lane_plan):
            add_event(
                trace,
                "lane_adjusted",
                "needs_review",
                {
                    "lane": "memory",
                    "reason": "Discovered memory lane still contains placeholder search terms.",
                    "decision": "Skip bounded memory triage until explicit case pivots are supplied.",
                },
            )
            continue
        lane_outputs[lane] = run_planned_lane_artifacts(
            trace=trace,
            lane=lane,
            lane_plan=lane_plan,
            plan_path=plan_path,
            output_root=output_root,
            config=config,
            max_attempts=max_attempts,
        )
        if lane == "disk":
            for disk_output in artifact_outputs(lane_outputs[lane]):
                record_disk_caveats(trace, disk_output)

    workflow_outputs: dict[str, Any] = dict(lane_outputs)
    claim_accuracy_status = "ok"
    correlation_outputs = correlate_planned_outputs(trace, lane_outputs, output_root)
    if correlation_outputs:
        workflow_outputs["correlation"] = correlation_outputs
        claims = write_claim_ledger(
            read_json(Path(correlation_outputs["summary"])),
            output_root / "claims",
        )
        workflow_outputs["claims"] = claims
        add_event(trace, "claim_ledger_completed", "ok", claims)
        quality = write_quality_review(
            read_json(Path(claims["summary"])),
            output_root / "quality",
        )
        workflow_outputs["quality"] = quality
        add_event(trace, "quality_review_completed", "ok", quality)
        accuracy = evaluate_planned_claim_accuracy(
            trace=trace,
            plan=plan,
            plan_path=plan_path,
            quality=quality,
            output_root=output_root,
        )
        if accuracy:
            workflow_outputs["claim_accuracy"] = accuracy
            claim_accuracy_status = "ok" if accuracy["passed"] else "needs_review"

    dossier_status = "ok"
    dossier_outputs = align_planned_profile(
        trace=trace,
        plan=plan,
        plan_path=plan_path,
        lane_outputs=lane_outputs,
        correlation_outputs=correlation_outputs,
        output_root=output_root,
    )
    if dossier_outputs:
        workflow_outputs["dossier"] = dossier_outputs["outputs"]
        dossier_status = "ok" if dossier_outputs["passed"] else "needs_review"

    trace["status"] = (
        "needs_review"
        if "needs_review" in {dossier_status, claim_accuracy_status}
        or trace_requires_review(trace)
        else "ok"
    )
    trace["outputs"] = workflow_outputs
    add_event(trace, "workflow_completed", trace["status"], {"status": trace["status"]})
    executive_outputs = write_executive_report(trace, output_root / "executive")
    trace["outputs"]["executive"] = executive_outputs
    return write_workflow_outputs(trace, output_root)


def run_rm_case_workflow(
    *,
    config: SiftVmConfig,
    output_root: Path,
    benchmark_root: Path,
    max_attempts: int = 2,
) -> dict[str, Any]:
    return run_case_workflow(
        config=config,
        case_plan_path=benchmark_root.parent / "cases" / "rm-stolen-szechuan-sauce.json",
        output_root=output_root,
        max_attempts=max_attempts,
    )


def run_planned_lane_artifacts(
    *,
    trace: dict[str, Any],
    lane: str,
    lane_plan: dict[str, Any],
    plan_path: Path,
    output_root: Path,
    config: SiftVmConfig,
    max_attempts: int,
) -> dict[str, Any]:
    artifacts = lane_artifacts(lane_plan)
    outputs = []
    for index, artifact_plan in enumerate(artifacts, start=1):
        try:
            outputs.append(
                run_planned_lane(
                    trace=trace,
                    lane=lane,
                    artifact_index=index,
                    artifact_count=len(artifacts),
                    lane_plan=artifact_plan,
                    plan_path=plan_path,
                    output_root=output_root,
                    config=config,
                    max_attempts=max_attempts,
                )
            )
        except Exception as error:
            add_event(
                trace,
                "lane_failed",
                "needs_review",
                {"lane": lane, "artifact": index, "reason": str(error)},
            )
            add_event(
                trace,
                "lane_adjusted",
                "needs_review",
                {
                    "lane": lane,
                    "artifact": index,
                    "reason": "Planned lane artifact did not complete.",
                    "decision": lane_failure_decision(len(artifacts)),
                },
            )
            outputs.append(
                {
                    "triage": None,
                    "validation": None,
                    "passed": False,
                    "error": str(error),
                }
            )
    if len(outputs) == 1:
        return outputs[0]
    return {
        "artifacts": outputs,
        "artifact_count": len(outputs),
        "passed": all(output["passed"] for output in outputs),
    }


def run_planned_lane(
    *,
    trace: dict[str, Any],
    lane: str,
    artifact_index: int,
    artifact_count: int,
    lane_plan: dict[str, Any],
    plan_path: Path,
    output_root: Path,
    config: SiftVmConfig,
    max_attempts: int,
) -> dict[str, Any]:
    runner = lane_runner(config, lane, lane_plan)
    default_output = lane if artifact_count == 1 else f"{lane}-{artifact_index:02d}"
    output_dir = output_root / lane_plan.get("output_dir", default_output)
    manifest = lane_plan.get("benchmark_manifest")
    if not manifest:
        return run_lane_once(
            trace=trace,
            lane=lane,
            artifact_index=artifact_index,
            output_dir=output_dir,
            runner=runner,
        )
    manifest_path = resolve_plan_reference(plan_path, manifest)
    validator = VALIDATORS.get(lane)
    if not validator:
        raise ValueError(f"unsupported benchmark validator for lane: {lane}")
    return run_lane_until_valid(
        trace=trace,
        lane=lane,
        artifact_index=artifact_index,
        output_dir=output_dir,
        manifest_path=manifest_path,
        runner=runner,
        validator=validator,
        max_attempts=max_attempts,
    )


def lane_runner(config: SiftVmConfig, lane: str, lane_plan: dict[str, Any]) -> LaneRunner:
    guest_path = lane_plan.get("guest_path")
    if not guest_path:
        raise ValueError(f"lane {lane} requires guest_path")
    if lane == "pcap":
        return lambda lane_output: triage_guest_pcap(
            config=config, guest_pcap_path=guest_path, output_dir=lane_output
        )
    if lane == "disk":
        return lambda lane_output: triage_guest_disk(
            config=config, guest_e01_path=guest_path, output_dir=lane_output
        )
    if lane == "autoruns":
        return lambda lane_output: triage_guest_autoruns(
            config=config, guest_zip_path=guest_path, output_dir=lane_output
        )
    if lane == "registry":
        return lambda lane_output: triage_guest_registry(
            config=config, guest_zip_path=guest_path, output_dir=lane_output
        )
    if lane == "userassist":
        return lambda lane_output: triage_guest_userassist(
            config=config, guest_zip_path=guest_path, output_dir=lane_output
        )
    if lane == "memory":
        terms = lane_plan.get("terms", [])
        if not terms:
            raise ValueError("memory lane requires at least one explicit term")
        return lambda lane_output: triage_guest_memory(
            config=config,
            guest_memory_path=guest_path,
            terms=terms,
            output_dir=lane_output,
        )
    raise ValueError(f"unsupported case-plan lane: {lane}")


def memory_lane_requires_terms_review(lane_plan: dict[str, Any]) -> bool:
    return any(
        artifact.get("terms") == ["pivot-to-review"]
        for artifact in lane_artifacts(lane_plan)
    )


def trace_requires_review(trace: dict[str, Any]) -> bool:
    return any(event["status"] == "needs_review" for event in trace.get("events", []))


def run_lane_once(
    *,
    trace: dict[str, Any],
    lane: str,
    artifact_index: int,
    output_dir: Path,
    runner: LaneRunner,
) -> dict[str, Any]:
    start = perf_counter()
    add_event(trace, "lane_started", "ok", {"lane": lane, "artifact": artifact_index, "attempt": 1})
    triage = runner(output_dir)
    add_event(
        trace,
        "lane_completed",
        "ok",
        {"lane": lane, "artifact": artifact_index, "elapsed_ms": round((perf_counter() - start) * 1000)},
    )
    return {"triage": triage, "validation": None, "passed": True}


def record_disk_caveats(trace: dict[str, Any], disk_output: dict[str, Any]) -> None:
    if not disk_output.get("triage"):
        return
    disk_summary = read_json(Path(disk_output["triage"]["summary"]))
    if disk_summary["disk"]["ewf_metadata"].get("is_corrupted") == "yes":
        add_event(
            trace,
            "degraded_evidence_decision",
            "ok",
            {
                "lane": "disk",
                "reason": "EWF metadata reports corruption.",
                "decision": "Prefer preserved exported host artifacts before relying on deeper disk extraction.",
            },
        )


def correlate_planned_outputs(
    trace: dict[str, Any],
    lane_outputs: dict[str, dict[str, Any]],
    output_root: Path,
) -> dict[str, str] | None:
    pcap_summary = lane_summary(lane_outputs, "pcap")
    disk_summary = lane_summary(lane_outputs, "disk")
    if not pcap_summary or not disk_summary:
        add_event(
            trace,
            "correlation_skipped",
            "ok",
            {"reason": "Completed PCAP and disk summaries are both required by current correlation."},
        )
        return None
    correlation_output = output_root / "correlation"
    correlation = correlate_case_summaries(
        pcap_summary,
        disk_summary,
        lane_summary(lane_outputs, "autoruns"),
        lane_summary(lane_outputs, "registry"),
        lane_summary(lane_outputs, "userassist"),
        lane_summary(lane_outputs, "memory"),
    )
    outputs = write_case_correlation(correlation, correlation_output)
    add_event(trace, "correlation_completed", "ok", {"output_dir": str(correlation_output), **outputs})
    return outputs


def align_planned_profile(
    *,
    trace: dict[str, Any],
    plan: dict[str, Any],
    plan_path: Path,
    lane_outputs: dict[str, dict[str, Any]],
    correlation_outputs: dict[str, str] | None,
    output_root: Path,
) -> dict[str, Any] | None:
    profile = plan.get("scenario_profile")
    required = {"pcap", "disk", "autoruns", "registry", "memory"}
    if not profile:
        return None
    required_summaries = {lane_summary(lane_outputs, lane) for lane in required}
    if not correlation_outputs or None in required_summaries:
        add_event(
            trace,
            "scenario_alignment_skipped",
            "needs_review",
            {"reason": "Scenario profile requires PCAP, disk, Autoruns, registry, memory, and correlation."},
        )
        return None
    dossier = align_case_profile(
        profile_path=resolve_plan_reference(plan_path, profile),
        pcap_summary_path=lane_summary(lane_outputs, "pcap"),
        disk_summary_path=lane_summary(lane_outputs, "disk"),
        autoruns_summary_path=lane_summary(lane_outputs, "autoruns"),
        registry_summary_path=lane_summary(lane_outputs, "registry"),
        memory_summary_path=lane_summary(lane_outputs, "memory"),
        correlation_summary_path=Path(correlation_outputs["summary"]),
    )
    outputs = write_case_dossier(dossier, output_root / "dossier")
    add_event(
        trace,
        "scenario_alignment_completed",
        "ok" if dossier["passed"] else "needs_review",
        {"score": dossier["score"], **outputs},
    )
    return {"passed": dossier["passed"], "outputs": outputs}


def evaluate_planned_claim_accuracy(
    *,
    trace: dict[str, Any],
    plan: dict[str, Any],
    plan_path: Path,
    quality: dict[str, str],
    output_root: Path,
) -> dict[str, str | bool] | None:
    manifest = plan.get("claim_accuracy_manifest")
    if not manifest:
        return None
    outputs = write_claim_accuracy(
        read_json(Path(quality["summary"])),
        resolve_plan_reference(plan_path, manifest),
        output_root / "claim-accuracy",
    )
    add_event(
        trace,
        "claim_accuracy_completed",
        "ok" if outputs["passed"] else "needs_review",
        outputs,
    )
    return outputs


def lane_summary(lane_outputs: dict[str, dict[str, Any]], lane: str) -> Path | None:
    output = lane_outputs.get(lane)
    if output and output.get("artifacts"):
        output = next((item for item in output["artifacts"] if item.get("triage")), None)
    triage = output.get("triage") if output else None
    return Path(triage["summary"]) if triage and triage.get("summary") else None


def artifact_outputs(lane_output: dict[str, Any]) -> list[dict[str, Any]]:
    return lane_output.get("artifacts", [lane_output])


def lane_failure_decision(artifact_count: int) -> str:
    if artifact_count > 1:
        return "Continue with remaining artifacts and preserve the failed artifact for review."
    return "Continue with remaining case lanes and preserve the failed lane for review."


def run_lane_until_valid(
    *,
    trace: dict[str, Any],
    lane: str,
    artifact_index: int,
    output_dir: Path,
    manifest_path: Path,
    runner: LaneRunner,
    validator: LaneValidator,
    max_attempts: int,
) -> dict[str, Any]:
    last_result: dict[str, Any] | None = None
    for attempt in range(1, max_attempts + 1):
        start = perf_counter()
        add_event(
            trace,
            "lane_started",
            "ok",
            {"lane": lane, "artifact": artifact_index, "attempt": attempt},
        )
        triage = runner(output_dir)
        validation = validator(Path(triage["summary"]), manifest_path)
        validation_path = output_dir / "validation.json"
        validation_path.write_text(json.dumps(validation, indent=2, sort_keys=True), encoding="utf-8")
        elapsed_ms = round((perf_counter() - start) * 1000)
        last_result = {
            "triage": triage,
            "validation": str(validation_path),
            "score": validation["score"],
            "passed": validation["passed"],
        }
        add_event(
            trace,
            "lane_validated",
            "ok" if validation["passed"] else "needs_retry",
            {
                "lane": lane,
                "artifact": artifact_index,
                "attempt": attempt,
                "elapsed_ms": elapsed_ms,
                "score": validation["score"],
                "validation": str(validation_path),
            },
        )
        if validation["passed"]:
            return last_result
        if attempt < max_attempts:
            add_event(
                trace,
                "bounded_retry",
                "ok",
                {
                    "lane": lane,
                    "artifact": artifact_index,
                    "failed_attempt": attempt,
                    "reason": "Benchmark validation did not pass.",
                },
            )

    raise RuntimeError(f"{lane} failed benchmark validation after {max_attempts} attempt(s): {last_result}")


def write_workflow_outputs(trace: dict[str, Any], output_root: Path) -> dict[str, Any]:
    log_path = output_root / "execution-log.json"
    report_path = output_root / "execution-report.md"
    log_path.write_text(json.dumps(trace, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_execution_report(trace), encoding="utf-8")
    return {
        "status": trace["status"],
        "execution_log": str(log_path),
        "execution_report": str(report_path),
        **trace["outputs"],
    }


def render_execution_report(trace: dict[str, Any]) -> str:
    rows = "\n".join(
        "| "
        + " | ".join(
            [
                event["timestamp"],
                event["event"],
                event["status"],
                summarize_event_details(event["details"]),
            ]
        )
        + " |"
        for event in trace["events"]
    )
    return f"""# Find Evil Case Execution Report

Generated: {trace["generated_at"]}

## Workflow

- Workflow: `{trace["workflow"]}`
- Case ID: `{trace.get("case_id", "unspecified")}`
- Case name: `{trace.get("case_name", "unspecified")}`
- Status: `{trace.get("status", "running")}`
- Maximum attempts per lane: `{trace["max_attempts"]}`

## Execution Trace

| Timestamp | Event | Status | Details |
| --- | --- | --- | --- |
{rows}
"""


def add_event(trace: dict[str, Any], event: str, status: str, details: dict[str, Any]) -> None:
    trace["events"].append(
        {
            "timestamp": utc_now(),
            "event": event,
            "status": status,
            "details": details,
        }
    )


def summarize_event_details(details: dict[str, Any]) -> str:
    return "; ".join(f"{key}={value}" for key, value in details.items()).replace("|", "\\|")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
