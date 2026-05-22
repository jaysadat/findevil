from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def render_pcap_report(summary: dict[str, Any]) -> str:
    metadata = summary["capture"]
    top_dns = _table_rows(summary["network"]["top_dns_queries"], ("value", "count"))
    top_http = _table_rows(summary["network"]["top_http_hosts"], ("value", "count"))
    top_tls = _table_rows(summary["network"]["top_tls_server_names"], ("value", "count"))
    executable_downloads = _table_rows(
        summary["network"].get("executable_http_downloads", []),
        ("ts", "source", "destination", "host", "uri", "mime_types"),
    )
    ssl_violations = _table_rows(
        summary["network"].get("ssl_protocol_violations", []),
        ("ts", "source", "destination", "destination_port", "message"),
    )
    top_services = _table_rows(
        summary["network"]["top_responder_services"],
        ("responder", "port", "proto", "service", "connections"),
    )
    notices = _notice_lines(summary["network"]["notices"])
    findings = "\n".join(f"- {finding}" for finding in summary["observations"])
    logs = "\n".join(
        f"- `{entry['name']}`: {entry['records']} records, {entry['size_bytes']} bytes"
        for entry in summary["zeek_logs"]
    )

    return f"""# Find Evil PCAP Triage Report

Generated: {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## Evidence Integrity

- Evidence path: `{summary["evidence"]["path"]}`
- SHA-256 before: `{summary["evidence"]["before_sha256"]}`
- SHA-256 after: `{summary["evidence"]["after_sha256"]}`
- Evidence unchanged: `{str(summary["evidence"]["unchanged"]).lower()}`

## Capture

- File type: {metadata.get("file_type", "unknown")}
- Packet count: {metadata.get("number_of_packets", "unknown")}
- Capture duration: {metadata.get("capture_duration", "unknown")}
- First packet: {metadata.get("first_packet_time", "unknown")}
- Last packet: {metadata.get("last_packet_time", "unknown")}

## Observations

{findings or "- No heuristic observations were emitted."}

## Top Responder Services

{top_services}

## Top DNS Queries

{top_dns}

## Top HTTP Hosts

{top_http}

## HTTP Executable Delivery Candidates

{executable_downloads}

## Top TLS Server Names

{top_tls}

## SSL Protocol Violation Pivots

{ssl_violations}

## Zeek Notices

{notices}

## Preserved Outputs

- `summary.json` contains structured tool output and command records.
- `zeek-logs.zip` contains raw Zeek logs copied from the SIFT guest.
- `guest-run.log` contains guest analyzer execution output.

### Zeek Log Inventory

{logs}
"""


def write_pcap_report(summary: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_pcap_report(summary), encoding="utf-8")


def render_disk_report(summary: dict[str, Any]) -> str:
    evidence_rows = _table_rows(
        [
            {
                "segment": Path(entry["path"]).name,
                "size_bytes": entry["size_bytes"],
                "sha256": entry["sha256"],
                "unchanged": entry["unchanged"],
            }
            for entry in summary["evidence"]["segments"]
        ],
        ("segment", "size_bytes", "sha256", "unchanged"),
    )
    partition_rows = _table_rows(
        summary["disk"]["partitions"],
        ("slot", "start", "end", "length", "description"),
    )
    artifact_rows = _table_rows(
        summary["filesystem"]["artifact_counts"],
        ("artifact", "count"),
    )
    artifact_samples = "\n".join(
        f"- `{artifact}`: " + ", ".join(f"`{path}`" for path in paths[:5])
        for artifact, paths in summary["filesystem"]["artifact_samples"].items()
        if paths
    )
    observations = "\n".join(f"- {finding}" for finding in summary["observations"])

    return f"""# Find Evil Disk Triage Report

Generated: {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## Evidence Integrity

- Primary image path: `{summary["evidence"]["primary_path"]}`
- All hashed EWF segments unchanged: `{str(summary["evidence"]["unchanged"]).lower()}`

{evidence_rows}

## Disk Metadata

- Case number: {summary["disk"]["ewf_metadata"].get("case_number", "unknown")}
- Description: {summary["disk"]["ewf_metadata"].get("description", "unknown")}
- Evidence number: {summary["disk"]["ewf_metadata"].get("evidence_number", "unknown")}
- EWF corruption flag: {summary["disk"]["ewf_metadata"].get("is_corrupted", "unknown")}
- Selected filesystem offset: `{summary["filesystem"]["offset_sectors"]}` sectors
- File system type: {summary["filesystem"]["metadata"].get("file_system_type", "unknown")}
- Volume serial number: {summary["filesystem"]["metadata"].get("volume_serial_number", "unknown")}

### Partition Table

{partition_rows}

## Observations

{observations or "- No heuristic observations were emitted."}

## Windows Artifact Surface

{artifact_rows}

### Artifact Samples

{artifact_samples or "- No artifact samples were emitted."}

## Preserved Outputs

- `summary.json` contains evidence hashes, command records, and artifact pivots.
- `tsk-outputs.zip` contains `ewfinfo`, `mmls`, `fsstat`, and recursive `fls` output.
- `guest-run.log` contains guest analyzer execution output.
"""


def write_disk_report(summary: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_disk_report(summary), encoding="utf-8")


def render_autoruns_report(summary: dict[str, Any]) -> str:
    category_rows = _table_rows(summary["autoruns"]["category_counts"], ("category", "count"))
    signer_rows = _table_rows(summary["autoruns"]["signer_counts"], ("signer_state", "count"))
    high_signal_rows = _table_rows(
        summary["autoruns"].get("high_signal_candidates", []),
        ("entry", "category", "image_path", "high_signal_reasons"),
    )
    candidate_rows = _table_rows(
        summary["autoruns"]["review_candidates"],
        ("entry", "category", "signer", "image_path", "reasons"),
    )
    observations = "\n".join(f"- {item}" for item in summary["observations"])
    return f"""# Find Evil Autoruns Triage Report

Generated: {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## Evidence Integrity

- ZIP path: `{summary["evidence"]["path"]}`
- ZIP SHA-256 before: `{summary["evidence"]["before_sha256"]}`
- ZIP SHA-256 after: `{summary["evidence"]["after_sha256"]}`
- Evidence unchanged: `{str(summary["evidence"]["unchanged"]).lower()}`
- CSV member: `{summary["autoruns"]["csv_member"]}`

## Observations

{observations}

## Autoruns Surface

- Parsed rows: `{summary["autoruns"]["row_count"]}`
- Enabled rows: `{summary["autoruns"]["enabled_count"]}`
- High-signal candidates: `{len(summary["autoruns"].get("high_signal_candidates", []))}`
- Review candidates: `{len(summary["autoruns"]["review_candidates"])}`

### Categories

{category_rows}

### Signer States

{signer_rows}

### High-Signal Persistence Pivots

{high_signal_rows}

### Review Candidates

{candidate_rows}

## Preserved Outputs

- `summary.json` contains the structured triage result.
- `autoruns-outputs.zip` contains the decoded CSV exported from the evidence ZIP.
- `guest-run.log` contains guest analyzer execution output.
"""


def write_autoruns_report(summary: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_autoruns_report(summary), encoding="utf-8")


def render_registry_report(summary: dict[str, Any]) -> str:
    high_signal_rows = _table_rows(
        summary["registry"]["high_signal_candidates"],
        ("entry", "kind", "value", "high_signal_reasons"),
    )
    run_rows = _table_rows(summary["registry"]["run_entries"], ("name", "command"))
    service_rows = _table_rows(
        summary["registry"]["service_entries"],
        ("name", "image_path", "type", "start"),
    )
    payload_rows = _table_rows(
        [
            {
                "key_path": entry["key_path"],
                "value_name": entry["value_name"],
                "run_entry": entry["run_entry"],
                "outer_indicators": ", ".join(entry["outer_script"]["indicators"]),
                "nested_indicators": ", ".join(
                    entry["nested_script"]["indicators"] if entry["nested_script"] else []
                ),
            }
            for entry in summary["registry"].get("decoded_payload_chains", [])
        ],
        ("key_path", "value_name", "run_entry", "outer_indicators", "nested_indicators"),
    )
    observations = "\n".join(f"- {item}" for item in summary["observations"])
    return f"""# Find Evil Protected Registry Triage Report

Generated: {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## Evidence Integrity

- ZIP path: `{summary["evidence"]["path"]}`
- ZIP SHA-256 before: `{summary["evidence"]["before_sha256"]}`
- ZIP SHA-256 after: `{summary["evidence"]["after_sha256"]}`
- Evidence unchanged: `{str(summary["evidence"]["unchanged"]).lower()}`
- Hive members: `{", ".join(summary["registry"]["hive_members"])}`

## Observations

{observations}

## High-Signal Registry Persistence Pivots

{high_signal_rows}

## Decoded Registry Payload Chains

{payload_rows}

## Run Entries

{run_rows}

## Service Entries

{service_rows}

## Preserved Outputs

- `summary.json` contains structured Run and service pivots.
- `registry-outputs.zip` contains the RegRipper plugin outputs and decoded
  referenced PowerShell text.
- `guest-run.log` contains guest analyzer execution output.
"""


def write_registry_report(summary: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_registry_report(summary), encoding="utf-8")


def render_userassist_report(summary: dict[str, Any]) -> str:
    profile_rows = _table_rows(
        summary["userassist"]["profiles"],
        ("profile", "member", "entry_count", "raw_output"),
    )
    execution_rows = _table_rows(
        summary["userassist"]["execution_entries"][:30],
        ("profile", "timestamp", "entry", "run_count", "executable_name"),
    )
    review_rows = _table_rows(
        summary["userassist"]["review_candidates"],
        ("profile", "timestamp", "entry", "run_count", "review_reason"),
    )
    observations = "\n".join(f"- {item}" for item in summary["observations"])
    return f"""# Find Evil UserAssist Triage Report

Generated: {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## Evidence Integrity

- ZIP path: `{summary["evidence"]["path"]}`
- ZIP SHA-256 before: `{summary["evidence"]["before_sha256"]}`
- ZIP SHA-256 after: `{summary["evidence"]["after_sha256"]}`
- Evidence unchanged: `{str(summary["evidence"]["unchanged"]).lower()}`

## Observations

{observations}

## Exported User Hives

{profile_rows}

## Timestamped Execution Entries

{execution_rows}

## Review Candidates

{review_rows}

## Preserved Outputs

- `summary.json` contains timestamped UserAssist execution entries and command records.
- `userassist-outputs.zip` contains RegRipper UserAssist plugin output for each exported hive.
- `guest-run.log` contains guest analyzer execution output.
"""


def write_userassist_report(summary: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_userassist_report(summary), encoding="utf-8")


def render_memory_report(summary: dict[str, Any]) -> str:
    count_rows = _table_rows(summary["memory"]["hit_counts"], ("term", "count"))
    sample_rows = _table_rows(
        [
            {"term": term, **sample}
            for term, samples in summary["memory"]["hit_samples"].items()
            for sample in samples
        ],
        ("term", "encoding", "line"),
    )
    observations = "\n".join(f"- {item}" for item in summary["observations"])
    return f"""# Find Evil Memory String Triage Report

Generated: {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## Evidence Integrity

- Memory path: `{summary["evidence"]["path"]}`
- SHA-256 before: `{summary["evidence"]["before_sha256"]}`
- SHA-256 after: `{summary["evidence"]["after_sha256"]}`
- Evidence unchanged: `{str(summary["evidence"]["unchanged"]).lower()}`

## Observations

{observations}

## Search Term Counts

{count_rows}

## Sampled String Hits

{sample_rows}

## Preserved Outputs

- `summary.json` contains string-hit counts and samples.
- `memory-string-hits.zip` contains matching ASCII and UTF-16LE string lines.
- `guest-run.log` contains guest analyzer execution output.
"""


def write_memory_report(summary: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_memory_report(summary), encoding="utf-8")


def render_case_inventory_report(inventory: dict[str, Any]) -> str:
    counts = _table_rows(inventory.get("candidate_counts", []), ("lane", "count"))
    candidates = _table_rows(
        [
            {
                "lane": entry["lane"],
                "guest_path": entry["guest_path"],
                "size_bytes": entry["size_bytes"],
                "reason": entry["reason"],
            }
            for entry in inventory.get("candidates", [])
        ],
        ("lane", "guest_path", "size_bytes", "reason"),
    )
    observations = "\n".join(f"- {item}" for item in inventory.get("observations", []))
    return f"""# Find Evil Case Inventory

Generated: {inventory["generated_at"]}

## Scope

- Guest case root: `{inventory["case_root"]}`
- Scanned files: `{inventory["scan"]["scanned_files"]}`
- Candidate artifacts: `{inventory["scan"]["candidate_count"]}`
- Scan truncated: `{str(inventory["scan"]["truncated"]).lower()}`

## Candidate Counts

{counts or "- No candidate lane counts emitted."}

## Candidate Artifacts

{candidates or "- No candidate evidence artifacts emitted."}

## Observations

{observations or "- No observations emitted."}
"""


def write_case_inventory_report(inventory: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(render_case_inventory_report(inventory), encoding="utf-8")


def build_executive_summary(trace: dict[str, Any]) -> dict[str, Any]:
    outputs = trace.get("outputs", {})
    lane_rows = []
    for lane in ("pcap", "disk", "autoruns", "registry", "userassist", "memory"):
        output = outputs.get(lane)
        if not output:
            continue
        items = output.get("artifacts", [output])
        lane_rows.append(
            {
                "lane": lane,
                "artifacts": len(items),
                "benchmarked": sum(1 for item in items if item.get("validation")),
                "passed": all(item.get("passed", False) for item in items),
            }
        )

    correlation = {}
    correlation_output = outputs.get("correlation")
    if correlation_output:
        correlation = json.loads(Path(correlation_output["summary"]).read_text(encoding="utf-8"))
    links = correlation.get("links", [])
    caveats = [
        event["details"]
        for event in trace.get("events", [])
        if event["event"]
        in {
            "degraded_evidence_decision",
            "lane_adjusted",
            "lane_failed",
            "correlation_skipped",
            "scenario_alignment_skipped",
        }
    ]
    signals = reviewed_executive_signals(outputs, links)
    if not signals:
        signals.append("No cross-artifact signal was promoted into the executive layer.")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "case_id": trace.get("case_id", "unspecified"),
        "case_name": trace.get("case_name", "unspecified"),
        "workflow_status": trace.get("status", "unknown"),
        "lane_summary": lane_rows,
        "signals": signals,
        "caveats": caveats,
        "next_actions": [
            "Review preserved lane reports and raw tool outputs before promoting findings.",
            "Prioritize corroborated pivots and evidence caveats in analyst handoff.",
            "Expand the case plan with additional host artifacts when case scope requires it.",
        ],
        "reporting_boundary": (
            "This executive summary reports triage status and supported pivots; "
            "it does not replace forensic finding review."
        ),
    }


def reviewed_executive_signals(outputs: dict[str, Any], links: list[dict[str, Any]]) -> list[str]:
    quality_output = outputs.get("quality")
    if quality_output:
        quality = json.loads(Path(quality_output["summary"]).read_text(encoding="utf-8"))
        return [claim["statement"] for claim in quality.get("promoted_claims", [])]
    signals = []
    for link in links:
        if link["type"] == "domain_hint_match":
            signals.append(f"Cross-artifact domain context was supported for {link['value']}.")
        if link["type"] == "persistence_corroboration":
            entries = ", ".join(item["entry"] for item in link["value"])
            signals.append(f"Persistence pivots were corroborated across host sources: {entries}.")
    return signals


def render_executive_report(summary: dict[str, Any]) -> str:
    lane_rows = _table_rows(
        summary["lane_summary"],
        ("lane", "artifacts", "benchmarked", "passed"),
    )
    signals = "\n".join(f"- {item}" for item in summary["signals"])
    caveats = "\n".join(
        f"- `{item.get('lane', 'workflow')}`: {item.get('reason', item.get('decision', item))}"
        + (f" Decision: {item['decision']}" if item.get("reason") and item.get("decision") else "")
        for item in summary["caveats"]
    )
    next_actions = "\n".join(f"- {item}" for item in summary["next_actions"])
    return f"""# Find Evil Executive Report

Generated: {summary["generated_at"]}

## Case Status

- Case ID: `{summary["case_id"]}`
- Case name: `{summary["case_name"]}`
- Workflow status: `{summary["workflow_status"]}`
- Reporting boundary: {summary["reporting_boundary"]}

## Evidence Processed

{lane_rows}

## Current Triage Signals

{signals}

## Caveats

{caveats or "- No workflow caveats were recorded."}

## Recommended Next Actions

{next_actions}
"""


def write_executive_report(trace: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = build_executive_summary(trace)
    summary_path = output_dir / "executive-summary.json"
    report_path = output_dir / "executive-report.md"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_executive_report(summary), encoding="utf-8")
    return {"summary": str(summary_path), "report": str(report_path)}


def build_claim_ledger(correlation: dict[str, Any]) -> dict[str, Any]:
    claims = []
    for index, link in enumerate(correlation.get("links", []), start=1):
        claim = claim_from_link(index, link, correlation.get("inputs", {}))
        if claim:
            claims.append(claim)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "claims": claims,
        "status_counts": [
            {"status": status, "count": sum(1 for claim in claims if claim["status"] == status)}
            for status in ("supported", "candidate", "corroborated_pivot", "volatile_pivot")
            if any(claim["status"] == status for claim in claims)
        ],
        "boundary": (
            "Claims remain pivots until an analyst reviews the referenced preserved outputs. "
            "Candidate and volatile pivots are not confirmed findings."
        ),
    }


def claim_from_link(index: int, link: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any] | None:
    link_type = link.get("type")
    source_keys = {
        "domain_hint_match": ("pcap_summary", "disk_summary"),
        "dc_network_pivot": ("pcap_summary", "disk_summary"),
        "autoruns_persistence_pivot": ("autoruns_summary",),
        "persistence_corroboration": ("autoruns_summary", "registry_summary"),
        "userassist_execution_corroboration": ("userassist_summary", "registry_summary"),
        "memory_string_pivot": ("memory_summary",),
    }.get(link_type)
    if not source_keys:
        return None
    if link_type == "domain_hint_match":
        statement = f"Domain context is supported across PCAP and disk hints: {link['value']}."
    elif link_type == "dc_network_pivot":
        statement = "Domain-controller network responder pivots were surfaced for review."
    elif link_type == "autoruns_persistence_pivot":
        statement = "Autoruns high-signal persistence pivots were surfaced for review."
    elif link_type == "persistence_corroboration":
        statement = (
            "Persistence pivots were corroborated across Autoruns and protected registry sources: "
            + ", ".join(item["entry"] for item in link["value"])
            + "."
        )
    elif link_type == "userassist_execution_corroboration":
        statement = (
            "UserAssist execution entries align with protected host pivots: "
            + ", ".join(item["entry"] for item in link["value"])
            + "."
        )
    else:
        statement = "Memory string pivots were preserved for explicit search terms."
    return {
        "claim_id": f"claim-{index:03d}",
        "type": link_type,
        "status": link.get("confidence", "candidate"),
        "statement": statement,
        "support": link.get("support", []),
        "source_summaries": [inputs[key] for key in source_keys if inputs.get(key)],
        "review_required": link.get("confidence") != "supported",
        "correlation_value": link.get("value"),
    }


def render_claim_ledger_report(ledger: dict[str, Any]) -> str:
    claim_rows = _table_rows(
        [
            {
                "claim_id": claim["claim_id"],
                "status": claim["status"],
                "type": claim["type"],
                "statement": claim["statement"],
                "sources": ", ".join(claim["source_summaries"]),
            }
            for claim in ledger["claims"]
        ],
        ("claim_id", "status", "type", "statement", "sources"),
    )
    status_rows = _table_rows(ledger["status_counts"], ("status", "count"))
    return f"""# Find Evil Claim Ledger

Generated: {ledger["generated_at"]}

## Reporting Boundary

{ledger["boundary"]}

## Claim Status Counts

{status_rows}

## Traceable Claims

{claim_rows}
"""


def write_claim_ledger(correlation: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = build_claim_ledger(correlation)
    summary_path = output_dir / "claim-ledger.json"
    report_path = output_dir / "claim-ledger.md"
    summary_path.write_text(json.dumps(ledger, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_claim_ledger_report(ledger), encoding="utf-8")
    return {"summary": str(summary_path), "report": str(report_path)}


def _table_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> str:
    if not rows:
        return "_None observed._"

    header = "| " + " | ".join(key.replace("_", " ").title() for key in keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    body = [
        "| " + " | ".join(str(row.get(key, "-")).replace("|", "\\|") for key in keys) + " |"
        for row in rows
    ]
    return "\n".join([header, separator, *body])


def _notice_lines(notices: list[dict[str, Any]]) -> str:
    if not notices:
        return "_No Zeek notice records observed._"

    return "\n".join(
        f"- `{notice.get('note', 'unknown')}` at `{notice.get('ts', '-')}`: "
        f"{notice.get('msg', '-')}"
        for notice in notices
    )
