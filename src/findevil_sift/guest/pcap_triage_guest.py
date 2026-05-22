from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ALLOWED_SUFFIXES = {".pcap", ".pcapng"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    pcap_path = validate_evidence_path(Path(args.pcap))
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    zeek_dir = output_dir / "zeek"
    zeek_dir.mkdir(exist_ok=True)

    command_records: list[dict[str, Any]] = []
    before = hash_file(pcap_path)
    capinfos = run_allowed(["capinfos", str(pcap_path)], command_records)
    run_allowed(["zeek", "readpcap", str(pcap_path), str(zeek_dir)], command_records)
    after = hash_file(pcap_path)

    summary = {
        "generated_at": utc_now(),
        "evidence": {
            "path": str(pcap_path),
            "before_sha256": before["sha256"],
            "after_sha256": after["sha256"],
            "size_bytes": before["size_bytes"],
            "unchanged": before == after,
        },
        "capture": parse_capinfos(capinfos["stdout"]),
        "commands": command_records,
        "zeek_logs": log_inventory(zeek_dir),
        "network": summarize_network(zeek_dir),
    }
    summary["observations"] = observations(summary)

    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    zip_logs(zeek_dir, output_dir / "zeek-logs.zip")
    return 0


def validate_evidence_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"PCAP evidence is not a file: {resolved}")
    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError(f"PCAP evidence must use one of {sorted(ALLOWED_SUFFIXES)}")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("PCAP evidence must live below /cases/")
    return resolved


def run_allowed(command: list[str], records: list[dict[str, Any]]) -> dict[str, str]:
    if command[0] not in {"capinfos", "zeek"}:
        raise ValueError(f"guest command is not allowlisted: {command[0]}")

    started_at = utc_now()
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    record = {
        "argv": command,
        "started_at": started_at,
        "finished_at": utc_now(),
        "returncode": completed.returncode,
        "stdout_preview": completed.stdout[-4000:],
        "stderr_preview": completed.stderr[-4000:],
    }
    records.append(record)
    if completed.returncode != 0:
        raise RuntimeError(f"guest command failed: {' '.join(command)}")
    return {"stdout": completed.stdout, "stderr": completed.stderr}


def hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size_bytes}


def parse_capinfos(output: str) -> dict[str, str]:
    wanted = {
        "File type": "file_type",
        "Number of packets": "number_of_packets",
        "Capture duration": "capture_duration",
        "First packet time": "first_packet_time",
        "Last packet time": "last_packet_time",
        "SHA256": "capinfos_sha256",
    }
    capture: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        if label in wanted:
            capture[wanted[label]] = value.strip()
    return capture


def summarize_network(zeek_dir: Path) -> dict[str, Any]:
    connections = list(read_zeek_log(zeek_dir / "conn.log"))
    dns = list(read_zeek_log(zeek_dir / "dns.log"))
    http = list(read_zeek_log(zeek_dir / "http.log"))
    ssl = list(read_zeek_log(zeek_dir / "ssl.log"))
    notices = list(read_zeek_log(zeek_dir / "notice.log"))
    files = list(read_zeek_log(zeek_dir / "files.log"))
    analyzer = list(read_zeek_log(zeek_dir / "analyzer.log"))

    responder_services = Counter(
        (
            row.get("id.resp_h", "-"),
            row.get("id.resp_p", "-"),
            row.get("proto", "-"),
            row.get("service", "-"),
        )
        for row in connections
    )
    return {
        "connection_count": len(connections),
        "dns_count": len(dns),
        "http_count": len(http),
        "tls_count": len(ssl),
        "notice_count": len(notices),
        "file_count": len(files),
        "top_responder_services": [
            {
                "responder": key[0],
                "port": key[1],
                "proto": key[2],
                "service": key[3],
                "connections": count,
            }
            for key, count in responder_services.most_common(12)
        ],
        "top_dns_queries": top_values(row.get("query") for row in dns),
        "dns_domain_hints": dns_domain_hints(dns),
        "top_http_hosts": top_values(row.get("host") for row in http),
        "executable_http_downloads": executable_http_downloads(http),
        "top_tls_server_names": top_values(row.get("server_name") for row in ssl),
        "private_http_destinations": private_http_destinations(http),
        "ssl_protocol_violations": ssl_protocol_violations(analyzer),
        "notices": [
            {"ts": row.get("ts"), "note": row.get("note"), "msg": row.get("msg")}
            for row in notices[:12]
        ],
        "file_mime_types": top_values(row.get("mime_type") for row in files),
    }


def read_zeek_log(path: Path) -> Iterable[dict[str, str]]:
    if not path.exists():
        return []

    fields: list[str] | None = None
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for line in handle:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                break
        if not fields:
            return []
        reader = csv.DictReader(handle, fieldnames=fields, delimiter="\t")
        return [row for row in reader if not row[fields[0]].startswith("#")]


def log_inventory(zeek_dir: Path) -> list[dict[str, Any]]:
    logs = []
    for path in sorted(zeek_dir.glob("*.log")):
        logs.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "records": sum(1 for _ in read_zeek_log(path)),
            }
        )
    return logs


def zip_logs(source_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.glob("*.log")):
            archive.write(path, arcname=path.name)


def top_values(values: Iterable[str | None], limit: int = 12) -> list[dict[str, Any]]:
    counter = Counter(value for value in values if value and value not in {"-", "(empty)"})
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def dns_domain_hints(dns_rows: list[dict[str, str]]) -> list[str]:
    hints = set()
    for row in dns_rows:
        query = (row.get("query") or "").strip(".").lower()
        if "." in query and query.endswith(".local"):
            labels = query.split(".")
            if len(labels) >= 2:
                hints.add(".".join(labels[-2:]))
    return sorted(hints)


def private_http_destinations(http_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    results = []
    for row in http_rows:
        destination = row.get("id.resp_h", "")
        try:
            is_private = ipaddress.ip_address(destination).is_private
        except ValueError:
            is_private = False
        if is_private:
            results.append(
                {
                    "destination": destination,
                    "host": row.get("host", "-"),
                    "uri": row.get("uri", "-"),
                    "status_code": row.get("status_code", "-"),
                }
            )
    return results[:12]


def executable_http_downloads(http_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    results = []
    for row in http_rows:
        uri = row.get("uri", "")
        mime_types = row.get("resp_mime_types", "")
        if not (uri.lower().endswith(".exe") or "application/x-dosexec" in mime_types.lower()):
            continue
        results.append(
            {
                "ts": row.get("ts", "-"),
                "source": row.get("id.orig_h", "-"),
                "destination": row.get("id.resp_h", "-"),
                "host": row.get("host", "-"),
                "uri": uri or "-",
                "status_code": row.get("status_code", "-"),
                "mime_types": mime_types or "-",
            }
        )
    return results[:12]


def ssl_protocol_violations(analyzer_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    results = []
    for row in analyzer_rows:
        if row.get("analyzer_name") != "SSL" or row.get("cause") != "violation":
            continue
        results.append(
            {
                "ts": row.get("ts", "-"),
                "source": row.get("id.orig_h", "-"),
                "destination": row.get("id.resp_h", "-"),
                "destination_port": row.get("id.resp_p", "-"),
                "message": row.get("failure_reason", "-"),
            }
        )
    return results[:12]


def observations(summary: dict[str, Any]) -> list[str]:
    network = summary["network"]
    emitted = [
        (
            f"Zeek produced {network['connection_count']} connection records, "
            f"{network['dns_count']} DNS records, and {network['http_count']} HTTP records."
        )
    ]
    if network["notice_count"]:
        emitted.append(
            f"Zeek emitted {network['notice_count']} notice records; review notice.log before "
            "promoting any network behavior to a confirmed finding."
        )
    if network["private_http_destinations"]:
        emitted.append(
            "HTTP responses from private destinations were observed; correlate them with "
            "case topology before treating them as internal services or redirects."
        )
    if network["executable_http_downloads"]:
        emitted.append(
            "HTTP executable delivery candidates were observed; review preserved Zeek HTTP and "
            "file logs before declaring payload delivery."
        )
    if network["ssl_protocol_violations"]:
        emitted.append(
            "Zeek analyzer records include SSL protocol violations; malformed encrypted traffic "
            "can be a useful callback pivot when correlated with host evidence."
        )
    if network["top_tls_server_names"]:
        emitted.append(
            "TLS server names are available for pivoting even where payload content is encrypted."
        )
    return emitted


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
