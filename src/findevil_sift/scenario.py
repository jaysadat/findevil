from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def align_case_profile(
    *,
    profile_path: Path,
    pcap_summary_path: Path,
    disk_summary_path: Path,
    autoruns_summary_path: Path,
    registry_summary_path: Path,
    memory_summary_path: Path,
    correlation_summary_path: Path,
) -> dict[str, Any]:
    profile = read_json(profile_path)
    pcap = read_json(pcap_summary_path)
    disk = read_json(disk_summary_path)
    autoruns = read_json(autoruns_summary_path)
    registry = read_json(registry_summary_path)
    memory = read_json(memory_summary_path)
    correlation = read_json(correlation_summary_path)

    payload = profile["expected_payload_download"]
    downloads = pcap["network"].get("executable_http_downloads", [])
    callback = profile["expected_callback_violation_destination"]
    ssl_violations = pcap["network"].get("ssl_protocol_violations", [])
    payload_matches = [
        row for row in downloads if all(row.get(key) == value for key, value in payload.items())
    ]
    callback_matches = [row for row in ssl_violations if row.get("destination") == callback]
    expected_persistence = set(profile["expected_corroborated_persistence"])
    corroborated = corroborated_persistence_entries(correlation)
    expected_memory_terms = set(profile["expected_memory_terms"])
    observed_memory_terms = {
        entry["term"] for entry in memory["memory"]["hit_counts"] if entry["count"] > 0
    }
    checks = [
        check(
            "evidence_integrity",
            all(
                [
                    pcap["evidence"]["unchanged"],
                    disk["evidence"]["unchanged"],
                    autoruns["evidence"]["unchanged"],
                    registry["evidence"]["unchanged"],
                    memory["evidence"]["unchanged"],
                ]
            ),
            "all workflow evidence hashes remain stable during lane analysis",
            {
                "pcap": pcap["evidence"]["unchanged"],
                "disk": disk["evidence"]["unchanged"],
                "autoruns": autoruns["evidence"]["unchanged"],
                "registry": registry["evidence"]["unchanged"],
                "memory": memory["evidence"]["unchanged"],
            },
        ),
        check(
            "payload_delivery",
            bool(payload_matches),
            payload,
            summarize_matches(payload_matches),
        ),
        check(
            "callback_network_hint",
            bool(callback_matches),
            callback,
            summarize_matches(callback_matches),
        ),
        check(
            "domain_context",
            profile["expected_domain_hint"] in correlation["hints"]["pcap_dns_domains"]
            and profile["expected_domain_hint"] in correlation["hints"]["disk_sysvol_domains"],
            profile["expected_domain_hint"],
            correlation["hints"],
        ),
        check(
            "persistence_corroboration",
            expected_persistence.issubset(corroborated),
            sorted(expected_persistence),
            sorted(corroborated),
        ),
        check(
            "volatile_pivot_corroboration",
            expected_memory_terms.issubset(observed_memory_terms),
            sorted(expected_memory_terms),
            sorted(observed_memory_terms),
        ),
    ]
    passed_checks = sum(1 for item in checks if item["passed"])
    return {
        "profile": profile,
        "generated_at": utc_now(),
        "inputs": {
            "pcap_summary": str(pcap_summary_path),
            "disk_summary": str(disk_summary_path),
            "autoruns_summary": str(autoruns_summary_path),
            "registry_summary": str(registry_summary_path),
            "memory_summary": str(memory_summary_path),
            "correlation_summary": str(correlation_summary_path),
        },
        "score": {"passed_checks": passed_checks, "total_checks": len(checks)},
        "passed": passed_checks == len(checks),
        "checks": checks,
        "evidence_notes": [
            "Scenario alignment checks compare extracted pivots to the training profile.",
            "They are regression and analyst-orientation checks, not a replacement for preserved artifact review.",
        ],
    }


def corroborated_persistence_entries(correlation: dict[str, Any]) -> set[str]:
    return {
        entry["entry"]
        for link in correlation["links"]
        if link["type"] == "persistence_corroboration"
        for entry in link["value"]
    }


def summarize_matches(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"match_count": len(rows), "samples": rows[:2]}


def write_case_dossier(dossier: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "case-dossier.json"
    report_path = output_dir / "case-dossier.md"
    summary_path.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(render_case_dossier(dossier), encoding="utf-8")
    return {"summary": str(summary_path), "report": str(report_path)}


def render_case_dossier(dossier: dict[str, Any]) -> str:
    profile = dossier["profile"]
    context = "\n".join(f"- {item}" for item in profile["case_context"])
    artifact_rows = table_rows(profile["artifact_roles"], ("artifact", "role"))
    check_rows = table_rows(
        [
            {
                "check": item["name"],
                "status": "pass" if item["passed"] else "fail",
                "expected": compact(item["expected"]),
                "observed": compact(item["observed"]),
            }
            for item in dossier["checks"]
        ],
        ("check", "status", "expected", "observed"),
    )
    notes = "\n".join(f"- {item}" for item in dossier["evidence_notes"])
    references = "\n".join(f"- {item}" for item in profile["references"])
    return f"""# Find Evil Case Dossier

Generated: {dossier["generated_at"]}

## Profile

- Case: `{profile["case_name"]}`
- Source: `{profile["case_owner"]}`
- Alignment score: `{dossier["score"]["passed_checks"]} / {dossier["score"]["total_checks"]}`
- Alignment status: `{"pass" if dossier["passed"] else "fail"}`

## Case Background

{context}

## Evidence Relationship

{artifact_rows}

## Scenario Alignment

{check_rows}

## Analyst Notes

{notes}

## Profile References

{references}
"""


def check(name: str, passed: bool, expected: Any, observed: Any) -> dict[str, Any]:
    return {"name": name, "passed": passed, "expected": expected, "observed": observed}


def table_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> str:
    header = "| " + " | ".join(key.replace("_", " ").title() for key in keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    body = [
        "| " + " | ".join(compact(row.get(key, "-")) for key in keys) + " |"
        for row in rows
    ]
    return "\n".join([header, separator, *body])


def compact(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    return str(value).replace("|", "\\|").replace("\n", " ")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Backward-compatible aliases for the original sample-case naming.
align_rm_case_profile = align_case_profile
write_rm_case_dossier = write_case_dossier
render_rm_case_dossier = render_case_dossier
