from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def validate_pcap_summary(summary_path: Path, manifest_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checks = [
        _check(
            "evidence_hash",
            summary["evidence"]["before_sha256"] == manifest["expected_sha256"],
            f"expected {manifest['expected_sha256']}",
            summary["evidence"]["before_sha256"],
        ),
        _check(
            "evidence_unchanged",
            bool(summary["evidence"]["unchanged"]),
            "before and after SHA-256 must match",
            summary["evidence"]["unchanged"],
        ),
    ]

    available_logs = {entry["name"] for entry in summary["zeek_logs"]}
    for log_name in manifest.get("required_logs", []):
        checks.append(
            _check(
                f"log:{log_name}",
                log_name in available_logs,
                "required Zeek log",
                log_name in available_logs,
            )
        )

    network = summary["network"]
    for metric, minimum in manifest.get("minimum_network_counts", {}).items():
        checks.append(
            _check(
                f"minimum:{metric}",
                network.get(metric, 0) >= minimum,
                f">= {minimum}",
                network.get(metric, 0),
            )
        )

    private_hosts = {entry["host"] for entry in network.get("private_http_destinations", [])}
    for host in manifest.get("expected_private_http_hosts", []):
        checks.append(
            _check(
                f"private_http_host:{host}",
                host in private_hosts,
                "expected private HTTP pivot",
                host in private_hosts,
            )
        )

    mime_types = {entry["value"] for entry in network.get("file_mime_types", [])}
    for mime_type in manifest.get("expected_file_mime_types", []):
        checks.append(
            _check(
                f"file_mime_type:{mime_type}",
                mime_type in mime_types,
                "expected extracted file MIME pivot",
                mime_type in mime_types,
            )
        )

    http_downloads = network.get("executable_http_downloads", [])
    for download in manifest.get("expected_http_executable_downloads", []):
        observed = any(
            all(row.get(key) == value for key, value in download.items())
            for row in http_downloads
        )
        checks.append(
            _check(
                f"http_executable_download:{download.get('uri', 'candidate')}",
                observed,
                download,
                observed,
            )
        )

    ssl_violations = network.get("ssl_protocol_violations", [])
    for violation in manifest.get("expected_ssl_violation_destinations", []):
        observed = any(row.get("destination") == violation for row in ssl_violations)
        checks.append(
            _check(
                f"ssl_violation_destination:{violation}",
                observed,
                "expected SSL protocol violation pivot",
                observed,
            )
        )

    return _validation_result("pcap", summary_path, manifest_path, manifest, checks)


def validate_disk_summary(summary_path: Path, manifest_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checks = [
        _check(
            "evidence_segment_count",
            summary["evidence"]["segment_count"] == manifest["expected_segment_count"],
            manifest["expected_segment_count"],
            summary["evidence"]["segment_count"],
        ),
        _check(
            "evidence_unchanged",
            bool(summary["evidence"]["unchanged"]),
            "all EWF segment hashes must match before and after",
            summary["evidence"]["unchanged"],
        ),
        _check(
            "filesystem_offset",
            int(summary["filesystem"]["offset_sectors"]) == int(manifest["expected_offset_sectors"]),
            str(manifest["expected_offset_sectors"]),
            summary["filesystem"]["offset_sectors"],
        ),
    ]

    segment_hashes = {Path(entry["path"]).name: entry["sha256"] for entry in summary["evidence"]["segments"]}
    for name, digest in manifest.get("expected_segment_sha256", {}).items():
        checks.append(
            _check(
                f"segment_hash:{name}",
                segment_hashes.get(name) == digest,
                digest,
                segment_hashes.get(name),
            )
        )

    artifact_counts = {
        entry["artifact"]: entry["count"] for entry in summary["filesystem"]["artifact_counts"]
    }
    for artifact, minimum in manifest.get("minimum_artifact_counts", {}).items():
        checks.append(
            _check(
                f"artifact_count:{artifact}",
                artifact_counts.get(artifact, 0) >= minimum,
                f">= {minimum}",
                artifact_counts.get(artifact, 0),
            )
        )

    metadata = summary["disk"]["ewf_metadata"]
    for key, expected in manifest.get("expected_ewf_metadata", {}).items():
        checks.append(_check(f"ewf_metadata:{key}", metadata.get(key) == expected, expected, metadata.get(key)))

    return _validation_result("disk", summary_path, manifest_path, manifest, checks)


def validate_autoruns_summary(summary_path: Path, manifest_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    autoruns = summary["autoruns"]
    checks = [
        _check(
            "evidence_hash",
            summary["evidence"]["before_sha256"] == manifest["expected_sha256"],
            manifest["expected_sha256"],
            summary["evidence"]["before_sha256"],
        ),
        _check(
            "evidence_unchanged",
            bool(summary["evidence"]["unchanged"]),
            "before and after SHA-256 must match",
            summary["evidence"]["unchanged"],
        ),
        _check(
            "csv_member",
            autoruns["csv_member"] == manifest["expected_csv_member"],
            manifest["expected_csv_member"],
            autoruns["csv_member"],
        ),
    ]

    for metric, minimum in manifest.get("minimum_autoruns_counts", {}).items():
        checks.append(
            _check(
                f"minimum:{metric}",
                autoruns.get(metric, 0) >= minimum,
                f">= {minimum}",
                autoruns.get(metric, 0),
            )
        )

    high_signal_entries = {entry["entry"] for entry in autoruns.get("high_signal_candidates", [])}
    for entry in manifest.get("expected_high_signal_entries", []):
        checks.append(
            _check(
                f"high_signal_entry:{entry}",
                entry in high_signal_entries,
                "expected high-signal Autoruns pivot",
                entry in high_signal_entries,
            )
        )

    return _validation_result("autoruns", summary_path, manifest_path, manifest, checks)


def validate_registry_summary(summary_path: Path, manifest_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    registry = summary["registry"]
    checks = [
        _check(
            "evidence_hash",
            summary["evidence"]["before_sha256"] == manifest["expected_sha256"],
            manifest["expected_sha256"],
            summary["evidence"]["before_sha256"],
        ),
        _check(
            "evidence_unchanged",
            bool(summary["evidence"]["unchanged"]),
            "before and after SHA-256 must match",
            summary["evidence"]["unchanged"],
        ),
    ]

    hive_members = set(registry["hive_members"])
    for member in manifest.get("required_hive_members", []):
        checks.append(
            _check(
                f"hive_member:{member}",
                member in hive_members,
                "required protected hive member",
                member in hive_members,
            )
        )

    for metric, minimum in manifest.get("minimum_registry_counts", {}).items():
        checks.append(
            _check(
                f"minimum:{metric}",
                registry.get(metric, 0) >= minimum,
                f">= {minimum}",
                registry.get(metric, 0),
            )
        )

    high_signal_entries = {entry["entry"] for entry in registry.get("high_signal_candidates", [])}
    for entry in manifest.get("expected_high_signal_entries", []):
        checks.append(
            _check(
                f"high_signal_entry:{entry}",
                entry in high_signal_entries,
                "expected high-signal registry pivot",
                entry in high_signal_entries,
            )
        )

    payload_refs = {
        f"{entry['key_path']}\\{entry['value_name']}": entry
        for entry in registry.get("decoded_payload_chains", [])
    }
    for reference, indicators in manifest.get("expected_decoded_payloads", {}).items():
        entry = payload_refs.get(reference)
        observed = set(entry["nested_script"]["indicators"]) if entry and entry["nested_script"] else set()
        checks.append(
            _check(
                f"decoded_payload:{reference}",
                bool(entry) and set(indicators).issubset(observed),
                indicators,
                sorted(observed),
            )
        )

    return _validation_result("registry", summary_path, manifest_path, manifest, checks)


def validate_memory_summary(summary_path: Path, manifest_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    memory = summary["memory"]
    checks = [
        _check(
            "evidence_hash",
            summary["evidence"]["before_sha256"] == manifest["expected_sha256"],
            manifest["expected_sha256"],
            summary["evidence"]["before_sha256"],
        ),
        _check(
            "evidence_unchanged",
            bool(summary["evidence"]["unchanged"]),
            "before and after SHA-256 must match",
            summary["evidence"]["unchanged"],
        ),
    ]
    hit_counts = {entry["term"]: entry["count"] for entry in memory["hit_counts"]}
    for term, minimum in manifest.get("minimum_term_hits", {}).items():
        checks.append(
            _check(
                f"term_hits:{term}",
                hit_counts.get(term, 0) >= minimum,
                f">= {minimum}",
                hit_counts.get(term, 0),
            )
        )
    return _validation_result("memory", summary_path, manifest_path, manifest, checks)


def validate_userassist_summary(summary_path: Path, manifest_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    userassist = summary["userassist"]
    checks = [
        _check(
            "evidence_hash",
            summary["evidence"]["before_sha256"] == manifest["expected_sha256"],
            manifest["expected_sha256"],
            summary["evidence"]["before_sha256"],
        ),
        _check(
            "evidence_unchanged",
            bool(summary["evidence"]["unchanged"]),
            "before and after SHA-256 must match",
            summary["evidence"]["unchanged"],
        ),
    ]
    for metric, minimum in manifest.get("minimum_userassist_counts", {}).items():
        checks.append(
            _check(
                f"minimum:{metric}",
                userassist.get(metric, 0) >= minimum,
                f">= {minimum}",
                userassist.get(metric, 0),
            )
        )
    members = set(userassist.get("hive_members", []))
    for member in manifest.get("required_hive_members", []):
        checks.append(
            _check(
                f"hive_member:{member}",
                member in members,
                "required exported NTUSER hive member",
                member in members,
            )
        )
    executable_names = {
        entry["executable_name"] for entry in userassist.get("execution_entries", [])
    }
    for executable_name in manifest.get("expected_executable_names", []):
        checks.append(
            _check(
                f"execution_entry:{executable_name}",
                executable_name.lower() in executable_names,
                "expected UserAssist execution entry",
                executable_name.lower() in executable_names,
            )
        )
    return _validation_result("userassist", summary_path, manifest_path, manifest, checks)


def _check(name: str, passed: bool, expected: Any, observed: Any) -> dict[str, Any]:
    return {
        "name": name,
        "passed": passed,
        "expected": expected,
        "observed": observed,
    }


def _validation_result(
    lane: str,
    summary_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    checks: list[dict[str, Any]],
) -> dict[str, Any]:
    passed_checks = sum(1 for check in checks if check["passed"])
    return {
        "benchmark_id": manifest["benchmark_id"],
        "lane": lane,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "summary_path": str(summary_path),
        "manifest_path": str(manifest_path),
        "passed": passed_checks == len(checks),
        "score": {
            "passed_checks": passed_checks,
            "total_checks": len(checks),
        },
        "checks": checks,
    }
