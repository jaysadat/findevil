from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NTUSER_MEMBER = re.compile(r"^Users/([^/]+)/NTUSER\.DAT$", re.IGNORECASE)
TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ$")
ENTRY = re.compile(r"^\s{2}(.+?) \((\d+)\)$")
REVIEW_ENTRY = re.compile(
    r"\b(powershell|cmd\.exe|cscript|wscript|mshta|rundll32|remote desktop)\b",
    re.IGNORECASE,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    zip_path = validate_zip_path(Path(args.zip))
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    decoded_dir = output_dir / "userassist"
    decoded_dir.mkdir(exist_ok=True)

    before = hash_file(zip_path)
    extracted = extract_ntuser_hives(zip_path, decoded_dir)
    hive_results = []
    command_records = [
        {
            "operation": "python_zipfile_extract",
            "inputs": [str(zip_path), *[item["member"] for item in extracted]],
            "outputs": [str(item["path"]) for item in extracted],
        }
    ]
    for item in extracted:
        raw_path = decoded_dir / f"{safe_label(item['profile'])}-userassist.txt"
        output = run_regripper(item["path"], raw_path)
        command_records.append(
            {
                "operation": "rip.pl",
                "inputs": [str(item["path"]), "userassist"],
                "outputs": [str(raw_path)],
            }
        )
        hive_results.append(
            {
                "profile": item["profile"],
                "member": item["member"],
                "raw_output": str(raw_path),
                "entries": parse_userassist_entries(output, item["profile"]),
            }
        )
    after = hash_file(zip_path)
    summary = {
        "generated_at": utc_now(),
        "evidence": {
            "path": str(zip_path),
            "before_sha256": before["sha256"],
            "after_sha256": after["sha256"],
            "size_bytes": before["size_bytes"],
            "unchanged": before == after,
        },
        "commands": command_records,
        "userassist": summarize_hives(extracted, hive_results),
    }
    summary["observations"] = observations(summary)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    zip_outputs(decoded_dir, output_dir / "userassist-outputs.zip")
    return 0


def validate_zip_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.suffix.lower() != ".zip":
        raise ValueError("UserAssist evidence must be a ZIP file")
    if not str(resolved).startswith("/cases/"):
        raise ValueError("UserAssist evidence must live below /cases/")
    return resolved


def extract_ntuser_hives(zip_path: Path, output_dir: Path) -> list[dict[str, Any]]:
    extracted = []
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.namelist():
            match = NTUSER_MEMBER.match(member)
            if not match:
                continue
            profile = match.group(1)
            destination = output_dir / f"{safe_label(profile)}-ntuser.dat"
            destination.write_bytes(archive.read(member))
            extracted.append({"profile": profile, "member": member, "path": destination})
    if not extracted:
        raise ValueError("UserAssist ZIP must contain Users/<profile>/NTUSER.DAT")
    return extracted


def run_regripper(hive_path: Path, destination: Path) -> str:
    completed = subprocess.run(
        ["rip.pl", "-r", str(hive_path), "-p", "userassist"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = completed.stdout + completed.stderr
    destination.write_text(output, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"RegRipper UserAssist plugin failed for {hive_path.name}")
    return output


def parse_userassist_entries(output: str, profile: str) -> list[dict[str, Any]]:
    entries = []
    last_timestamp = None
    for line in output.splitlines():
        stripped = line.strip()
        if TIMESTAMP.match(stripped):
            last_timestamp = stripped
            continue
        match = ENTRY.match(line)
        if not match or not last_timestamp:
            continue
        value = match.group(1)
        entries.append(
            {
                "profile": profile,
                "timestamp": last_timestamp,
                "entry": value,
                "run_count": int(match.group(2)),
                "executable_name": executable_name(value),
            }
        )
    return entries


def summarize_hives(extracted: list[dict[str, Any]], hive_results: list[dict[str, Any]]) -> dict[str, Any]:
    entries = [entry for hive in hive_results for entry in hive["entries"]]
    candidates = [
        {**entry, "review_reason": "lolbin_or_remote_access_execution_pivot"}
        for entry in entries
        if REVIEW_ENTRY.search(entry["entry"])
    ]
    return {
        "hive_members": [item["member"] for item in extracted],
        "profile_count": len(extracted),
        "entry_count": len(entries),
        "profiles": [
            {
                "profile": hive["profile"],
                "member": hive["member"],
                "entry_count": len(hive["entries"]),
                "raw_output": Path(hive["raw_output"]).name,
            }
            for hive in hive_results
        ],
        "execution_entries": entries[:120],
        "review_candidates": candidates[:30],
    }


def executable_name(value: str) -> str:
    token = value.replace("\\", "/").rsplit("/", 1)[-1]
    return token.lower()


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower() or "profile"


def observations(summary: dict[str, Any]) -> list[str]:
    userassist = summary["userassist"]
    return [
        f"Parsed timestamped UserAssist entries from {userassist['profile_count']} exported NTUSER hive(s).",
        f"{userassist['entry_count']} timestamped execution entries were preserved for review.",
        (
            f"{len(userassist['review_candidates'])} UserAssist entries matched execution review heuristics; "
            "UserAssist remains execution context, not malware classification."
        ),
    ]


def hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size_bytes}


def zip_outputs(source_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.iterdir()):
            if path.suffix.lower() == ".txt":
                archive.write(path, arcname=path.name)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
