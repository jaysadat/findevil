from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def correlate_case_summaries(
    pcap_summary_path: Path,
    disk_summary_path: Path,
    autoruns_summary_path: Path | None = None,
    registry_summary_path: Path | None = None,
    userassist_summary_path: Path | None = None,
    memory_summary_path: Path | None = None,
) -> dict[str, Any]:
    pcap = json.loads(pcap_summary_path.read_text(encoding="utf-8"))
    disk = json.loads(disk_summary_path.read_text(encoding="utf-8"))
    autoruns = (
        json.loads(autoruns_summary_path.read_text(encoding="utf-8"))
        if autoruns_summary_path
        else None
    )
    registry = (
        json.loads(registry_summary_path.read_text(encoding="utf-8"))
        if registry_summary_path
        else None
    )
    userassist = (
        json.loads(userassist_summary_path.read_text(encoding="utf-8"))
        if userassist_summary_path
        else None
    )
    memory = (
        json.loads(memory_summary_path.read_text(encoding="utf-8"))
        if memory_summary_path
        else None
    )
    pcap_domains = set(pcap["network"].get("dns_domain_hints", []))
    disk_domains = set(disk["filesystem"].get("domain_hints", []))
    matched_domains = sorted(pcap_domains & disk_domains)
    disk_artifacts = {entry["artifact"]: entry["count"] for entry in disk["filesystem"]["artifact_counts"]}
    responder_services = pcap["network"].get("top_responder_services", [])

    links = []
    for domain in matched_domains:
        links.append(
            {
                "type": "domain_hint_match",
                "value": domain,
                "support": [
                    "PCAP DNS domain hint",
                    "Disk SYSVOL domain hint",
                ],
                "confidence": "supported",
            }
        )

    if disk_artifacts.get("ntds_database") and responder_services:
        links.append(
            {
                "type": "dc_network_pivot",
                "value": responder_services[:5],
                "support": [
                    "Disk NTDS database path identified",
                    "PCAP responder service concentration",
                ],
                "confidence": "candidate",
            }
        )

    if autoruns:
        pivots = autoruns["autoruns"].get("high_signal_candidates", [])
        if pivots:
            links.append(
                {
                    "type": "autoruns_persistence_pivot",
                    "value": pivots[:5],
                    "support": [
                        "Exported Autoruns row",
                        "High-signal persistence heuristic",
                    ],
                    "confidence": "candidate",
                }
            )

    corroborated_persistence = []
    if autoruns and registry:
        autoruns_entries = {
            entry["entry"]: entry
            for entry in autoruns["autoruns"].get("high_signal_candidates", [])
        }
        registry_entries = {
            entry["entry"]: entry
            for entry in registry["registry"].get("high_signal_candidates", [])
        }
        for entry in sorted(autoruns_entries.keys() & registry_entries.keys()):
            corroborated_persistence.append(
                {
                    "entry": entry,
                    "autoruns": autoruns_entries[entry],
                    "registry": registry_entries[entry],
                }
            )
        if corroborated_persistence:
            links.append(
                {
                    "type": "persistence_corroboration",
                    "value": corroborated_persistence,
                    "support": [
                        "Exported Autoruns high-signal pivot",
                        "Protected registry high-signal pivot",
                    ],
                    "confidence": "corroborated_pivot",
                }
            )

    userassist_execution = []
    if userassist:
        userassist_entries = {
            executable_stem(entry["executable_name"]): entry
            for entry in userassist["userassist"].get("execution_entries", [])
            if entry.get("executable_name")
        }
        host_pivots = {}
        for source in (autoruns, registry):
            if not source:
                continue
            key = "autoruns" if "autoruns" in source else "registry"
            for entry in source[key].get("high_signal_candidates", []):
                host_pivots[executable_stem(entry["entry"])] = entry
        for entry_name in sorted(set(userassist_entries) & set(host_pivots)):
            userassist_execution.append(
                {
                    "entry": entry_name,
                    "userassist": userassist_entries[entry_name],
                    "host_pivot": host_pivots[entry_name],
                }
            )
        if userassist_execution:
            links.append(
                {
                    "type": "userassist_execution_corroboration",
                    "value": userassist_execution,
                    "support": [
                        "Exported UserAssist timestamped execution entry",
                        "Host high-signal persistence pivot",
                    ],
                    "confidence": "corroborated_pivot",
                }
            )

    memory_hits = []
    if memory:
        memory_hits = [
            entry for entry in memory["memory"].get("hit_counts", []) if entry["count"] > 0
        ]
        if memory_hits:
            links.append(
                {
                    "type": "memory_string_pivot",
                    "value": memory_hits,
                    "support": [
                        "Bounded memory ASCII and UTF-16LE string search",
                        "Explicit case pivot terms",
                    ],
                    "confidence": "volatile_pivot",
                }
            )

    observations = []
    if matched_domains:
        observations.append(
            f"PCAP DNS and disk SYSVOL both expose domain hint(s): {', '.join(matched_domains)}."
        )
    if disk_artifacts.get("ntds_database"):
        observations.append(
            "The disk lane identifies an NTDS database path; use PCAP responder pivots to prioritize "
            "domain-controller network activity review."
        )
    if autoruns and autoruns["autoruns"].get("high_signal_candidates"):
        observations.append(
            "The Autoruns lane identifies high-signal persistence pivots for host follow-up."
        )
    if corroborated_persistence:
        observations.append(
            "Autoruns and protected registry lanes corroborate persistence pivots: "
            + ", ".join(entry["entry"] for entry in corroborated_persistence)
            + "."
        )
    if userassist_execution:
        observations.append(
            "UserAssist execution entries align with protected host pivots: "
            + ", ".join(entry["entry"] for entry in userassist_execution)
            + "."
        )
    if memory_hits:
        observations.append(
            "Memory strings preserve volatile pivot hits for: "
            + ", ".join(entry["term"] for entry in memory_hits)
            + "."
        )
    observations.append(
        "Correlation links summarize pivots only. Promote findings only after reviewing preserved lane outputs."
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "inputs": {
            "pcap_summary": str(pcap_summary_path),
            "disk_summary": str(disk_summary_path),
            "autoruns_summary": str(autoruns_summary_path) if autoruns_summary_path else None,
            "registry_summary": str(registry_summary_path) if registry_summary_path else None,
            "userassist_summary": str(userassist_summary_path) if userassist_summary_path else None,
            "memory_summary": str(memory_summary_path) if memory_summary_path else None,
        },
        "evidence_integrity": {
            "pcap_unchanged": pcap["evidence"]["unchanged"],
            "disk_unchanged": disk["evidence"]["unchanged"],
            "autoruns_unchanged": autoruns["evidence"]["unchanged"] if autoruns else None,
            "registry_unchanged": registry["evidence"]["unchanged"] if registry else None,
            "userassist_unchanged": userassist["evidence"]["unchanged"] if userassist else None,
            "memory_unchanged": memory["evidence"]["unchanged"] if memory else None,
        },
        "hints": {
            "pcap_dns_domains": sorted(pcap_domains),
            "disk_sysvol_domains": sorted(disk_domains),
        },
        "links": links,
        "observations": observations,
    }


def render_case_correlation(correlation: dict[str, Any]) -> str:
    domain_links = [
        link for link in correlation["links"] if link["type"] == "domain_hint_match"
    ]
    candidate_links = [
        link for link in correlation["links"] if link["type"] == "dc_network_pivot"
    ]
    autoruns_links = [
        link for link in correlation["links"] if link["type"] == "autoruns_persistence_pivot"
    ]
    corroboration_links = [
        link for link in correlation["links"] if link["type"] == "persistence_corroboration"
    ]
    userassist_links = [
        link for link in correlation["links"] if link["type"] == "userassist_execution_corroboration"
    ]
    memory_links = [
        link for link in correlation["links"] if link["type"] == "memory_string_pivot"
    ]
    observations = "\n".join(f"- {item}" for item in correlation["observations"])
    domains = ", ".join(link["value"] for link in domain_links) or "None"
    responders = "\n".join(
        f"- `{entry['responder']}:{entry['port']}/{entry['proto']}` "
        f"service `{entry['service']}`: {entry['connections']} connections"
        for link in candidate_links
        for entry in link["value"]
    )
    autoruns_pivots = "\n".join(
        f"- `{entry['entry']}` in `{entry['category']}`: `{entry['image_path']}` "
        f"({entry['high_signal_reasons']})"
        for link in autoruns_links
        for entry in link["value"]
    )
    registry_pivots = "\n".join(
        f"- `{entry['entry']}`: Autoruns `{entry['autoruns']['category']}` and registry "
        f"`{entry['registry']['kind']}` pivot"
        for link in corroboration_links
        for entry in link["value"]
    )
    memory_pivots = "\n".join(
        f"- `{entry['term']}`: {entry['count']} matching memory string line(s)"
        for link in memory_links
        for entry in link["value"]
    )
    autoruns_input = correlation["inputs"]["autoruns_summary"] or "Not provided"
    registry_input = correlation["inputs"]["registry_summary"] or "Not provided"
    userassist_input = correlation["inputs"]["userassist_summary"] or "Not provided"
    memory_input = correlation["inputs"]["memory_summary"] or "Not provided"
    autoruns_integrity = correlation["evidence_integrity"]["autoruns_unchanged"]
    autoruns_integrity_text = (
        str(autoruns_integrity).lower() if autoruns_integrity is not None else "not checked"
    )
    registry_integrity = correlation["evidence_integrity"]["registry_unchanged"]
    registry_integrity_text = (
        str(registry_integrity).lower() if registry_integrity is not None else "not checked"
    )
    userassist_integrity = correlation["evidence_integrity"]["userassist_unchanged"]
    userassist_integrity_text = (
        str(userassist_integrity).lower() if userassist_integrity is not None else "not checked"
    )
    userassist_pivots = "\n".join(
        f"- `{entry['entry']}` at `{entry['userassist']['timestamp']}` for "
        f"`{entry['userassist']['profile']}`"
        for link in userassist_links
        for entry in link["value"]
    )
    memory_integrity = correlation["evidence_integrity"]["memory_unchanged"]
    memory_integrity_text = (
        str(memory_integrity).lower() if memory_integrity is not None else "not checked"
    )
    return f"""# Find Evil Case Correlation

Generated: {correlation["generated_at"]}

## Inputs

- PCAP summary: `{correlation["inputs"]["pcap_summary"]}`
- Disk summary: `{correlation["inputs"]["disk_summary"]}`
- Autoruns summary: `{autoruns_input}`
- Registry summary: `{registry_input}`
- UserAssist summary: `{userassist_input}`
- Memory summary: `{memory_input}`
- PCAP evidence unchanged: `{str(correlation["evidence_integrity"]["pcap_unchanged"]).lower()}`
- Disk evidence unchanged: `{str(correlation["evidence_integrity"]["disk_unchanged"]).lower()}`
- Autoruns evidence unchanged: `{autoruns_integrity_text}`
- Registry evidence unchanged: `{registry_integrity_text}`
- UserAssist evidence unchanged: `{userassist_integrity_text}`
- Memory evidence unchanged: `{memory_integrity_text}`

## Supported Domain Links

- Matched domain hints: `{domains}`
- PCAP DNS hints: `{", ".join(correlation["hints"]["pcap_dns_domains"]) or "None"}`
- Disk SYSVOL hints: `{", ".join(correlation["hints"]["disk_sysvol_domains"]) or "None"}`

## Candidate DC Network Pivots

{responders or "- No candidate responder pivots emitted."}

## Candidate Autoruns Persistence Pivots

{autoruns_pivots or "- No Autoruns persistence pivots emitted."}

## Corroborated Persistence Pivots

{registry_pivots or "- No cross-artifact registry corroboration emitted."}

## UserAssist Execution Corroboration

{userassist_pivots or "- No UserAssist execution corroboration emitted."}

## Volatile Memory String Pivots

{memory_pivots or "- No memory string pivots emitted."}

## Observations

{observations}
"""


def write_case_correlation(correlation: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "correlation.json"
    report_path = output_dir / "correlation.md"
    summary_path.write_text(json.dumps(correlation, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_case_correlation(correlation), encoding="utf-8")
    return {"summary": str(summary_path), "report": str(report_path)}


def executable_stem(value: str) -> str:
    name = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.rsplit(".", 1)[0]
