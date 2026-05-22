from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_SUFFIXES = {".e01"}
ARTIFACT_PATTERNS = {
    "event_logs": re.compile(r"Windows/System32/winevt/Logs/.+\.evtx$", re.IGNORECASE),
    "registry_hives": re.compile(
        r"Windows/System32/config/(SYSTEM|SOFTWARE|SECURITY|SAM)$",
        re.IGNORECASE,
    ),
    "amcache": re.compile(r"Windows/AppCompat/Programs/Amcache\.hve$", re.IGNORECASE),
    "ntuser_hives": re.compile(r"Users/[^/]+/NTUSER\.DAT$", re.IGNORECASE),
    "srum": re.compile(r"Windows/System32/sru/SRUDB\.dat$", re.IGNORECASE),
    "scheduled_tasks": re.compile(r"Windows/System32/Tasks/.+", re.IGNORECASE),
    "prefetch": re.compile(r"Windows/Prefetch/.+\.pf$", re.IGNORECASE),
    "powershell_paths": re.compile(r"PowerShell", re.IGNORECASE),
    "ntds_database": re.compile(r"Windows/NTDS/ntds\.dit$", re.IGNORECASE),
    "ntds_logs": re.compile(r"Windows/NTDS/.+\.(log|jrs|chk)$", re.IGNORECASE),
    "sysvol_paths": re.compile(r"Windows/SYSVOL/", re.IGNORECASE),
    "group_policy_registry": re.compile(r"Registry\.pol$", re.IGNORECASE),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--e01", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    image_path = validate_image_path(Path(args.e01))
    output_dir = args.output_dir
    raw_dir = output_dir / "tsk"
    raw_dir.mkdir(parents=True, exist_ok=True)
    command_records: list[dict[str, Any]] = []

    segments_before = hash_segments(segment_paths(image_path))
    ewfinfo = run_allowed(["ewfinfo", str(image_path)], command_records)
    mmls = run_allowed(["mmls", str(image_path)], command_records)
    partitions = parse_mmls(mmls["stdout"])
    target = select_ntfs_partition(partitions)
    fsstat = run_allowed(
        ["fsstat", "-o", target["start"], str(image_path)],
        command_records,
    )
    fls = run_allowed(
        ["fls", "-r", "-o", target["start"], "-p", str(image_path)],
        command_records,
    )
    segments_after = hash_segments(segment_paths(image_path))

    (raw_dir / "ewfinfo.txt").write_text(ewfinfo["stdout"], encoding="utf-8")
    (raw_dir / "mmls.txt").write_text(mmls["stdout"], encoding="utf-8")
    (raw_dir / "fsstat.txt").write_text(fsstat["stdout"], encoding="utf-8")
    (raw_dir / "fls.txt").write_text(fls["stdout"], encoding="utf-8")

    summary = {
        "generated_at": utc_now(),
        "evidence": summarize_evidence(image_path, segments_before, segments_after),
        "commands": command_records,
        "disk": {
            "ewf_metadata": parse_ewfinfo(ewfinfo["stdout"]),
            "partitions": partitions,
        },
        "filesystem": summarize_filesystem(
            target_offset=target["start"],
            fsstat_text=fsstat["stdout"],
            fls_text=fls["stdout"],
        ),
    }
    summary["observations"] = observations(summary)

    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    zip_outputs(raw_dir, output_dir / "tsk-outputs.zip")
    return 0


def validate_image_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"E01 evidence is not a file: {resolved}")
    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError("disk triage currently requires an .E01 primary segment")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("disk evidence must live below /cases/")
    return resolved


def segment_paths(image_path: Path) -> list[Path]:
    segments = [
        path
        for path in image_path.parent.iterdir()
        if path.is_file() and re.fullmatch(r"\.e\d\d", path.suffix.lower())
    ]
    return sorted(segments, key=lambda path: path.suffix.lower())


def hash_segments(paths: list[Path]) -> list[dict[str, Any]]:
    return [{"path": str(path), **hash_file(path)} for path in paths]


def hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size_bytes}


def run_allowed(command: list[str], records: list[dict[str, Any]]) -> dict[str, str]:
    if command[0] not in {"ewfinfo", "mmls", "fsstat", "fls"}:
        raise ValueError(f"guest command is not allowlisted: {command[0]}")

    started_at = utc_now()
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    records.append(
        {
            "argv": command,
            "started_at": started_at,
            "finished_at": utc_now(),
            "returncode": completed.returncode,
            "stdout_preview": completed.stdout[-4000:],
            "stderr_preview": completed.stderr[-4000:],
        }
    )
    if completed.returncode != 0:
        raise RuntimeError(f"guest command failed: {' '.join(command)}")
    return {"stdout": completed.stdout, "stderr": completed.stderr}


def parse_ewfinfo(output: str) -> dict[str, str]:
    labels = {
        "Case number": "case_number",
        "Description": "description",
        "Evidence number": "evidence_number",
        "Examiner name": "examiner_name",
        "Acquisition date": "acquisition_date",
        "Is corrupted": "is_corrupted",
        "Media size": "media_size",
    }
    metadata: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        if label in labels:
            metadata[labels[label]] = value.strip()
    return metadata


def parse_mmls(output: str) -> list[dict[str, str]]:
    partitions = []
    for line in output.splitlines():
        match = re.match(
            r"^(?P<slot>\d{3}:|---:)\s+(?P<meta>\S+)\s+"
            r"(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<length>\d+)\s+(?P<description>.+)$",
            line.strip(),
        )
        if not match:
            continue
        partitions.append(
            {
                "slot": f"{match.group('slot')} {match.group('meta')}",
                "start": match.group("start"),
                "end": match.group("end"),
                "length": match.group("length"),
                "description": match.group("description").strip(),
            }
        )
    return partitions


def select_ntfs_partition(partitions: list[dict[str, str]]) -> dict[str, str]:
    ntfs = [partition for partition in partitions if "NTFS" in partition["description"]]
    if not ntfs:
        raise ValueError("no NTFS partition was found in mmls output")
    return max(ntfs, key=lambda partition: int(partition["length"]))


def summarize_filesystem(target_offset: str, fsstat_text: str, fls_text: str) -> dict[str, Any]:
    paths = [parse_fls_path(line) for line in fls_text.splitlines()]
    real_paths = [path for path in paths if path]
    artifact_samples: dict[str, list[str]] = defaultdict(list)
    artifact_counts = Counter()
    for path in real_paths:
        for artifact, pattern in ARTIFACT_PATTERNS.items():
            if pattern.search(path):
                artifact_counts[artifact] += 1
                if len(artifact_samples[artifact]) < 12:
                    artifact_samples[artifact].append(path)

    return {
        "offset_sectors": target_offset,
        "metadata": parse_fsstat(fsstat_text),
        "fls_path_count": len(real_paths),
        "deleted_path_count": sum(1 for line in fls_text.splitlines() if "*" in line.split(":", 1)[0]),
        "domain_hints": domain_hints(real_paths),
        "artifact_counts": [
            {"artifact": artifact, "count": count}
            for artifact, count in artifact_counts.most_common()
        ],
        "artifact_samples": dict(sorted(artifact_samples.items())),
    }


def parse_fsstat(output: str) -> dict[str, str]:
    labels = {
        "File System Type": "file_system_type",
        "Volume Serial Number": "volume_serial_number",
        "Volume Name": "volume_name",
        "Sector Size": "sector_size",
        "Cluster Size": "cluster_size",
        "Root Directory": "root_directory",
    }
    metadata: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        if label in labels:
            metadata[labels[label]] = value.strip()
    return metadata


def parse_fls_path(line: str) -> str | None:
    if ":" not in line or line.startswith(("File", "Error")):
        return None
    _, path = line.split(":", 1)
    path = path.strip()
    return path or None


def domain_hints(paths: list[str]) -> list[str]:
    hints = set()
    for path in paths:
        match = re.search(r"Windows/SYSVOL/(?:sysvol|staging areas)/([^/]+)", path, re.IGNORECASE)
        if match:
            hints.add(match.group(1).lower())
    return sorted(hints)


def summarize_evidence(
    image_path: Path,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> dict[str, Any]:
    after_by_path = {entry["path"]: entry for entry in after}
    segments = []
    for entry in before:
        after_entry = after_by_path[entry["path"]]
        segments.append(
            {
                **entry,
                "after_sha256": after_entry["sha256"],
                "unchanged": entry["sha256"] == after_entry["sha256"],
            }
        )
    return {
        "primary_path": str(image_path),
        "segment_count": len(segments),
        "segments": segments,
        "unchanged": all(entry["unchanged"] for entry in segments),
    }


def observations(summary: dict[str, Any]) -> list[str]:
    filesystem = summary["filesystem"]
    counts = {entry["artifact"]: entry["count"] for entry in filesystem["artifact_counts"]}
    emitted = [
        (
            f"Sleuth Kit listed {filesystem['fls_path_count']} filesystem paths from "
            f"the selected NTFS partition at sector offset {filesystem['offset_sectors']}."
        )
    ]
    if counts.get("event_logs"):
        emitted.append(
            f"{counts['event_logs']} Windows event log paths were identified for later targeted parsing."
        )
    if counts.get("registry_hives") or counts.get("amcache"):
        emitted.append(
            "Registry and Amcache paths are present for a later execution and persistence lane."
        )
    if counts.get("ntds_database"):
        emitted.append(
            "The NTDS database path is present, confirming a domain-controller-specific extraction pivot."
        )
    if counts.get("sysvol_paths"):
        emitted.append(
            f"{counts['sysvol_paths']} SYSVOL paths were identified for policy and script review."
        )
    if summary["disk"]["ewf_metadata"].get("is_corrupted", "").lower() == "yes":
        emitted.append(
            "EWF metadata reports the image corruption flag as yes; preserve that caveat in later findings."
        )
    return emitted


def zip_outputs(source_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.iterdir()):
            archive.write(path, arcname=path.name)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
