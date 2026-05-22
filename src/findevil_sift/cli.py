from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .benchmarks import (
    validate_autoruns_summary,
    validate_disk_summary,
    validate_pcap_summary,
    validate_memory_summary,
    validate_registry_summary,
    validate_userassist_summary,
)
from .case_plans import (
    load_and_validate_case_plan,
    write_case_plan_template,
    write_discovered_case_plan,
)
from .correlate import correlate_case_summaries, write_case_correlation
from .tools import hash_evidence
from .vmware import (
    SiftVmConfig,
    triage_guest_autoruns,
    triage_guest_disk,
    triage_guest_pcap,
    triage_guest_memory,
    triage_guest_registry,
    triage_guest_userassist,
    inventory_guest_case,
)
from .workflow import run_case_workflow, run_rm_case_workflow


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="findevil-sift")
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser(
        "hash-evidence",
        help="Hash a file and emit an audit record with before/after snapshots.",
    )
    hash_parser.add_argument("path", type=Path)

    pcap_parser = subparsers.add_parser(
        "pcap-triage",
        help="Run constrained Zeek PCAP triage inside the SIFT guest.",
    )
    pcap_parser.add_argument("guest_pcap_path")
    pcap_parser.add_argument("--output-dir", type=Path, required=True)
    pcap_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    disk_parser = subparsers.add_parser(
        "disk-triage",
        help="Run constrained Sleuth Kit triage against an E01 below /cases.",
    )
    disk_parser.add_argument("guest_e01_path")
    disk_parser.add_argument("--output-dir", type=Path, required=True)
    disk_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    autoruns_parser = subparsers.add_parser(
        "autoruns-triage",
        help="Run constrained triage for an Autoruns ZIP exported below /cases.",
    )
    autoruns_parser.add_argument("guest_zip_path")
    autoruns_parser.add_argument("--output-dir", type=Path, required=True)
    autoruns_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    registry_parser = subparsers.add_parser(
        "registry-triage",
        help="Run constrained RegRipper triage for protected SOFTWARE and SYSTEM hives.",
    )
    registry_parser.add_argument("guest_zip_path")
    registry_parser.add_argument("--output-dir", type=Path, required=True)
    registry_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    userassist_parser = subparsers.add_parser(
        "userassist-triage",
        help="Run constrained UserAssist triage for exported NTUSER hives inside a ZIP.",
    )
    userassist_parser.add_argument("guest_zip_path")
    userassist_parser.add_argument("--output-dir", type=Path, required=True)
    userassist_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    memory_parser = subparsers.add_parser(
        "memory-triage",
        help="Run bounded memory string-hit triage for explicit search terms.",
    )
    memory_parser.add_argument("guest_memory_path")
    memory_parser.add_argument("--term", action="append", required=True)
    memory_parser.add_argument("--output-dir", type=Path, required=True)
    memory_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    validate_parser = subparsers.add_parser(
        "validate-pcap-summary",
        help="Validate one PCAP triage summary against a benchmark manifest.",
    )
    validate_parser.add_argument("summary", type=Path)
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.add_argument("--output", type=Path)

    validate_disk_parser = subparsers.add_parser(
        "validate-disk-summary",
        help="Validate one disk triage summary against a benchmark manifest.",
    )
    validate_disk_parser.add_argument("summary", type=Path)
    validate_disk_parser.add_argument("manifest", type=Path)
    validate_disk_parser.add_argument("--output", type=Path)

    validate_autoruns_parser = subparsers.add_parser(
        "validate-autoruns-summary",
        help="Validate one Autoruns triage summary against a benchmark manifest.",
    )
    validate_autoruns_parser.add_argument("summary", type=Path)
    validate_autoruns_parser.add_argument("manifest", type=Path)
    validate_autoruns_parser.add_argument("--output", type=Path)

    validate_registry_parser = subparsers.add_parser(
        "validate-registry-summary",
        help="Validate one protected registry triage summary against a benchmark manifest.",
    )
    validate_registry_parser.add_argument("summary", type=Path)
    validate_registry_parser.add_argument("manifest", type=Path)
    validate_registry_parser.add_argument("--output", type=Path)

    validate_memory_parser = subparsers.add_parser(
        "validate-memory-summary",
        help="Validate one memory triage summary against a benchmark manifest.",
    )
    validate_memory_parser.add_argument("summary", type=Path)
    validate_memory_parser.add_argument("manifest", type=Path)
    validate_memory_parser.add_argument("--output", type=Path)

    validate_userassist_parser = subparsers.add_parser(
        "validate-userassist-summary",
        help="Validate one UserAssist triage summary against a benchmark manifest.",
    )
    validate_userassist_parser.add_argument("summary", type=Path)
    validate_userassist_parser.add_argument("manifest", type=Path)
    validate_userassist_parser.add_argument("--output", type=Path)

    correlate_parser = subparsers.add_parser(
        "correlate-case",
        help="Correlate preserved PCAP, disk, and optional host-artifact summaries.",
    )
    correlate_parser.add_argument("pcap_summary", type=Path)
    correlate_parser.add_argument("disk_summary", type=Path)
    correlate_parser.add_argument("--autoruns-summary", type=Path)
    correlate_parser.add_argument("--registry-summary", type=Path)
    correlate_parser.add_argument("--userassist-summary", type=Path)
    correlate_parser.add_argument("--memory-summary", type=Path)
    correlate_parser.add_argument("--output-dir", type=Path, required=True)

    init_plan_parser = subparsers.add_parser(
        "init-case-plan",
        help="Create an editable case-plan JSON template.",
    )
    init_plan_parser.add_argument("output", type=Path)
    init_plan_parser.add_argument("--case-id", required=True)
    init_plan_parser.add_argument("--case-name", required=True)
    init_plan_parser.add_argument(
        "--lane",
        action="append",
        choices=("pcap", "disk", "autoruns", "registry", "userassist", "memory"),
        help="Add one lane to the template. Omit to include every current lane.",
    )

    validate_plan_parser = subparsers.add_parser(
        "validate-case-plan",
        help="Validate a case-plan JSON before a workflow run.",
    )
    validate_plan_parser.add_argument("case_plan", type=Path)
    validate_plan_parser.add_argument("--output", type=Path)

    discover_parser = subparsers.add_parser(
        "discover-case",
        help="Inventory a SIFT case root and optionally draft a reviewable case plan.",
    )
    discover_parser.add_argument("guest_case_root")
    discover_parser.add_argument("--output-dir", type=Path, required=True)
    discover_parser.add_argument("--plan-output", type=Path)
    discover_parser.add_argument("--case-id")
    discover_parser.add_argument("--case-name")
    discover_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    workflow_parser = subparsers.add_parser(
        "run-case",
        help="Run a plan-driven multi-artifact case workflow.",
    )
    workflow_parser.add_argument("case_plan", type=Path)
    workflow_parser.add_argument("--output-dir", type=Path, required=True)
    workflow_parser.add_argument("--max-attempts", type=int, default=2)
    workflow_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    rm_workflow_parser = subparsers.add_parser(
        "run-rm-case",
        help="Compatibility command for the bundled R&M sample case plan.",
    )
    rm_workflow_parser.add_argument("--output-dir", type=Path, required=True)
    rm_workflow_parser.add_argument("--benchmark-root", type=Path, default=Path("benchmarks"))
    rm_workflow_parser.add_argument("--max-attempts", type=int, default=2)
    rm_workflow_parser.add_argument(
        "--vmx-path",
        default=None,
        help="Override SIFT_VMX_PATH or the discovered local default.",
    )

    args = parser.parse_args(argv)
    if args.command == "hash-evidence":
        print(json.dumps(hash_evidence(args.path).to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "pcap-triage":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = triage_guest_pcap(
            config=config,
            guest_pcap_path=args.guest_pcap_path,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "disk-triage":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = triage_guest_disk(
            config=config,
            guest_e01_path=args.guest_e01_path,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "autoruns-triage":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = triage_guest_autoruns(
            config=config,
            guest_zip_path=args.guest_zip_path,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "registry-triage":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = triage_guest_registry(
            config=config,
            guest_zip_path=args.guest_zip_path,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "userassist-triage":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = triage_guest_userassist(
            config=config,
            guest_zip_path=args.guest_zip_path,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "memory-triage":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = triage_guest_memory(
            config=config,
            guest_memory_path=args.guest_memory_path,
            terms=args.term,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "validate-pcap-summary":
        result = validate_pcap_summary(args.summary, args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "validate-disk-summary":
        result = validate_disk_summary(args.summary, args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "validate-autoruns-summary":
        result = validate_autoruns_summary(args.summary, args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "validate-registry-summary":
        result = validate_registry_summary(args.summary, args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "validate-memory-summary":
        result = validate_memory_summary(args.summary, args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "validate-userassist-summary":
        result = validate_userassist_summary(args.summary, args.manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "correlate-case":
        correlation = correlate_case_summaries(
            args.pcap_summary,
            args.disk_summary,
            args.autoruns_summary,
            args.registry_summary,
            args.userassist_summary,
            args.memory_summary,
        )
        outputs = write_case_correlation(correlation, args.output_dir)
        print(json.dumps({"status": "ok", **outputs}, indent=2, sort_keys=True))
        return 0
    if args.command == "init-case-plan":
        result = write_case_plan_template(
            args.output,
            case_id=args.case_id,
            case_name=args.case_name,
            lanes=args.lane or [],
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "validate-case-plan":
        _, result = load_and_validate_case_plan(args.case_plan)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    if args.command == "discover-case":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = inventory_guest_case(
            config=config,
            guest_case_root=args.guest_case_root,
            output_dir=args.output_dir,
        )
        if args.plan_output:
            if not args.case_id or not args.case_name:
                parser.error("discover-case --plan-output requires --case-id and --case-name")
            inventory = json.loads(Path(result["inventory"]).read_text(encoding="utf-8"))
            result["draft_plan"] = write_discovered_case_plan(
                args.plan_output,
                inventory,
                case_id=args.case_id,
                case_name=args.case_name,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "run-case":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = run_case_workflow(
            config=config,
            case_plan_path=args.case_plan,
            output_root=args.output_dir,
            max_attempts=args.max_attempts,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "run-rm-case":
        config = SiftVmConfig.from_environment(vmx_path=args.vmx_path)
        result = run_rm_case_workflow(
            config=config,
            output_root=args.output_dir,
            benchmark_root=args.benchmark_root,
            max_attempts=args.max_attempts,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
